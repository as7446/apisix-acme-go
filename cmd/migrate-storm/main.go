package main

import (
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"gorm.io/gorm/clause"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	infragorm "github.com/as7446/apisix-acme-go/internal/infra/gorm"
)

// Certificate matches the old Storm gob type by exported field names.
type Certificate struct {
	ID           int
	Domain       string
	SNIs         []string
	NotBefore    int64
	NotAfter     int64
	APISIXID     string
	Fingerprint  string
	SerialNumber string
	CreatedAt    int64
	UpdatedAt    int64
	LastRenewAt  int64
	RenewLockAt  int64
	Deleted      bool
	DeletedAt    int64
	Status       string
	Source       string
	LastSyncedAt int64
	SyncError    string
	Revision     int64
	Renewing     bool
	LastIssuedAt int64
	AcmeOrderURL string
}

type migrationOptions struct {
	stormPath        string
	configPath       string
	certDir          string
	execute          bool
	includeDeleted   bool
	challengeZone    string
	syncZones        []string
	source           string
	syncStatus       string
	limit            int
	domains          map[string]struct{}
	reportPath       string
	skipMissingFiles bool
}

type migrationItem struct {
	Old        Certificate
	Selected   bool
	Eligible   bool
	Reason     string
	Warnings   []string
	CertPath   string
	KeyPath    string
	CertPEM    string
	KeyPEM     string
	Metadata   *cert.CertMetadata
	Revision   int64
	APISIXID   string
	FileStatus string
}

type migrationStats struct {
	Total        int
	Eligible     int
	Selected     int
	Skipped      int
	Deleted      int
	MissingFiles int
	InvalidFiles int
	Warnings     int
	Migrated     int
	Failed       int
}

func main() {
	opts := migrationOptions{}
	var syncZones string
	var domains string
	flag.StringVar(&opts.stormPath, "storm-db", "", "old Storm/BoltDB cert metadata path, e.g. out/certs.db")
	flag.StringVar(&opts.configPath, "config", "config.controller.example.yml", "controller config path with MySQL DSN")
	flag.StringVar(&opts.certDir, "cert-dir", "", "old local cert root dir, e.g. /path/to/apisix_acme/out")
	flag.BoolVar(&opts.execute, "execute", false, "write to MySQL; default is dry-run")
	flag.BoolVar(&opts.includeDeleted, "include-deleted", false, "also migrate deleted old records")
	flag.StringVar(&opts.challengeZone, "challenge-zone", "", "default challenge_zone for migrated active certs")
	flag.StringVar(&syncZones, "sync-zones", "", "default sync_zones for migrated active certs, comma-separated; empty means all online agents")
	flag.StringVar(&opts.source, "source", string(cert.CertSourceManaged), "cert source: managed or external")
	flag.StringVar(&opts.syncStatus, "sync-status", string(cert.SyncSynced), "new sync_status for migrated active certs: synced/drifted")
	flag.IntVar(&opts.limit, "limit", 0, "migrate at most N eligible certificates; useful for gray migration")
	flag.StringVar(&domains, "domains", "", "only migrate comma-separated domains")
	flag.StringVar(&opts.reportPath, "report", "", "write migration report CSV")
	flag.BoolVar(&opts.skipMissingFiles, "skip-missing-files", false, "skip missing/invalid cert files instead of failing execute preflight")
	flag.Parse()

	if opts.stormPath == "" {
		log.Fatal("-storm-db is required")
	}
	if opts.certDir == "" {
		log.Fatal("-cert-dir is required")
	}
	if opts.execute && opts.configPath == "" {
		log.Fatal("-config is required in execute mode")
	}
	opts.syncZones = splitCSV(syncZones)
	opts.domains = stringSet(splitCSV(domains))

	records, err := readStormCertificates(opts.stormPath)
	if err != nil {
		log.Fatalf("read storm db: %v", err)
	}
	if len(records) == 0 {
		log.Fatal("no Certificate records decoded from storm db")
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Domain < records[j].Domain
	})

	now := time.Now().Unix()
	items, stats := buildMigrationPlan(records, opts, now)
	printSummary(stats, opts)
	printPreview(items, opts)

	if opts.reportPath != "" {
		if err := writeReport(opts.reportPath, items); err != nil {
			log.Fatalf("write report: %v", err)
		}
		fmt.Printf("report written: %s\n", opts.reportPath)
	}

	if !opts.execute {
		fmt.Println("dry-run only. add -execute to write MySQL.")
		return
	}
	if stats.Selected == 0 {
		log.Fatal("no eligible certificates selected for migration")
	}
	if !opts.skipMissingFiles && (stats.MissingFiles > 0 || stats.InvalidFiles > 0) {
		log.Fatalf("preflight failed: missing_files=%d invalid_files=%d; fix files or use -skip-missing-files", stats.MissingFiles, stats.InvalidFiles)
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	store, err := infragorm.New(cfg)
	if err != nil {
		log.Fatalf("open mysql: %v", err)
	}
	defer store.Close()
	certRepo := infragorm.NewCertRepo(store.DB)

	for i := range items {
		if !items[i].Selected {
			continue
		}
		if err := migrateOne(store, certRepo, &items[i], opts); err != nil {
			stats.Failed++
			log.Fatalf("migrate %s: %v", items[i].Old.Domain, err)
		}
		stats.Migrated++
		fmt.Printf("migrated domain=%s revision=%d not_after=%d\n", items[i].Old.Domain, items[i].Revision, items[i].Metadata.NotAfter)
	}

	fmt.Printf("migration finished: migrated=%d failed=%d selected=%d\n", stats.Migrated, stats.Failed, stats.Selected)
	fmt.Println("note: migrated certificates are active/idle. use Web UI batch sync if APISIX labels need normalization.")
}

func buildMigrationPlan(records []Certificate, opts migrationOptions, now int64) ([]migrationItem, migrationStats) {
	items := make([]migrationItem, 0, len(records))
	stats := migrationStats{Total: len(records)}
	selected := 0

	for _, old := range records {
		item := migrationItem{Old: old, Revision: normalizedRevision(old), APISIXID: normalizedAPISIXID(old)}
		if old.Deleted {
			stats.Deleted++
		}

		if reason := oldRecordSkipReason(old, opts, now); reason != "" {
			item.Reason = reason
			stats.Skipped++
			items = append(items, item)
			continue
		}

		validateCertificateFiles(&item, opts, now)
		if item.Reason != "" {
			stats.Skipped++
			if strings.Contains(item.Reason, "missing") {
				stats.MissingFiles++
			}
			if strings.Contains(item.Reason, "invalid") || strings.Contains(item.Reason, "expired") {
				stats.InvalidFiles++
			}
			items = append(items, item)
			continue
		}

		item.Eligible = true
		stats.Eligible++
		stats.Warnings += len(item.Warnings)
		if opts.limit <= 0 || selected < opts.limit {
			item.Selected = true
			selected++
			stats.Selected++
		} else {
			item.Reason = "limit exceeded"
		}
		items = append(items, item)
	}
	return items, stats
}

func oldRecordSkipReason(old Certificate, opts migrationOptions, now int64) string {
	if len(opts.domains) > 0 {
		if _, ok := opts.domains[old.Domain]; !ok {
			return "domain filter"
		}
	}
	if old.Deleted && !opts.includeDeleted {
		return "deleted"
	}
	if old.Domain == "" {
		return "empty domain"
	}
	if old.NotAfter <= now {
		return "storm metadata expired"
	}
	if !isInUseStatus(old.Status) {
		return "status not in use"
	}
	return ""
}

func validateCertificateFiles(item *migrationItem, opts migrationOptions, now int64) {
	certPath, keyPath := certificateFilePaths(opts.certDir, item.Old.Domain)
	item.CertPath = certPath
	item.KeyPath = keyPath
	item.FileStatus = "ok"

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		item.Reason = "missing cert file"
		item.FileStatus = "cert missing"
		if opts.skipMissingFiles {
			return
		}
		return
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		item.Reason = "missing key file"
		item.FileStatus = "key missing"
		return
	}
	if !looksLikePrivateKey(string(keyPEM)) {
		item.Reason = "invalid key pem"
		item.FileStatus = "invalid key"
		return
	}

	metadata, err := cert.ParseCertMetadata(string(certPEM))
	if err != nil {
		item.Reason = "invalid cert pem: " + err.Error()
		item.FileStatus = "invalid cert"
		return
	}
	if metadata.NotAfter <= now {
		item.Reason = "file cert expired"
		item.FileStatus = "cert expired"
		return
	}

	item.CertPEM = string(certPEM)
	item.KeyPEM = string(keyPEM)
	item.Metadata = metadata

	if item.Old.Fingerprint != "" && item.Old.Fingerprint != metadata.Fingerprint {
		item.Warnings = append(item.Warnings, "fingerprint mismatch: use file metadata")
	}
	if item.Old.SerialNumber != "" && item.Old.SerialNumber != metadata.SerialNumber {
		item.Warnings = append(item.Warnings, "serial_number mismatch: use file metadata")
	}
	if item.Old.NotAfter != 0 && item.Old.NotAfter != metadata.NotAfter {
		item.Warnings = append(item.Warnings, "not_after mismatch: use file metadata")
	}
	if item.Old.NotBefore != 0 && item.Old.NotBefore != metadata.NotBefore {
		item.Warnings = append(item.Warnings, "not_before mismatch: use file metadata")
	}
}

func migrateOne(store *infragorm.Store, certRepo *infragorm.CertRepo, item *migrationItem, opts migrationOptions) error {
	model := toCertModel(item, opts)
	if err := upsertCertModel(store, model); err != nil {
		return err
	}
	return certRepo.ImportCertContent(item.Old.Domain, item.Revision, item.CertPEM, item.KeyPEM)
}

func readStormCertificates(path string) ([]Certificate, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	byDomain := make(map[string]Certificate)
	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return walkBucket(b, func(_ string, key, value []byte) {
				var c Certificate
				if err := gob.NewDecoder(bytes.NewReader(value)).Decode(&c); err != nil {
					return
				}
				if !isStormCertRecord(c) {
					return
				}
				existing, ok := byDomain[c.Domain]
				if !ok || c.UpdatedAt >= existing.UpdatedAt {
					byDomain[c.Domain] = c
				}
				_ = key
			})
		})
	})
	if err != nil {
		return nil, err
	}

	records := make([]Certificate, 0, len(byDomain))
	for _, c := range byDomain {
		records = append(records, c)
	}
	return records, nil
}

func isStormCertRecord(c Certificate) bool {
	return c.Domain != "" && c.NotAfter > 0
}

func walkBucket(b *bolt.Bucket, visit func(bucketPath string, key, value []byte)) error {
	return walkBucketPath("", b, visit)
}

func walkBucketPath(path string, b *bolt.Bucket, visit func(bucketPath string, key, value []byte)) error {
	return b.ForEach(func(k, v []byte) error {
		if v == nil {
			child := b.Bucket(k)
			if child == nil {
				return nil
			}
			nextPath := string(k)
			if path != "" {
				nextPath = path + "/" + nextPath
			}
			return walkBucketPath(nextPath, child, visit)
		}
		visit(path, k, v)
		return nil
	})
}

func toCertModel(item *migrationItem, opts migrationOptions) *infragorm.CertModel {
	old := item.Old
	now := uint64(time.Now().Unix())
	createdAt := uint64(old.CreatedAt)
	if createdAt == 0 {
		createdAt = now
	}
	updatedAt := uint64(old.UpdatedAt)
	if updatedAt == 0 {
		updatedAt = createdAt
	}
	lastIssuedAt := uint64(old.LastIssuedAt)
	if lastIssuedAt == 0 && old.Status == "issued" {
		lastIssuedAt = updatedAt
	}
	lastSyncedAt := uint64(old.LastSyncedAt)
	if lastSyncedAt == 0 && old.Status == "issued" {
		lastSyncedAt = updatedAt
	}

	lifecycleStatus, issueStatus, syncStatus := mapOldStatus(old, opts)
	source := opts.source
	if old.Source != "" {
		source = old.Source
	}
	if source == "" {
		source = string(cert.CertSourceManaged)
	}

	return &infragorm.CertModel{
		Domain:          old.Domain,
		LifecycleStatus: string(lifecycleStatus),
		SyncStatus:      string(syncStatus),
		CurrentRevision: uint(item.Revision),
		NotBefore:       uint64(item.Metadata.NotBefore),
		NotAfter:        uint64(item.Metadata.NotAfter),
		APISIXID:        item.APISIXID,
		Fingerprint:     item.Metadata.Fingerprint,
		SerialNumber:    item.Metadata.SerialNumber,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		LastRenewAt:     uint64(old.LastRenewAt),
		Deleted:         old.Deleted,
		DeletedAt:       uint64(old.DeletedAt),
		Source:          source,
		LastSyncedAt:    lastSyncedAt,
		SyncError:       old.SyncError,
		IssueStatus:     string(issueStatus),
		LastIssuedAt:    lastIssuedAt,
		ChallengeZone:   opts.challengeZone,
		SyncZones:       toJSONArray(opts.syncZones),
		RetryCount:      0,
		NextRetryAt:     0,
	}
}

func mapOldStatus(old Certificate, opts migrationOptions) (cert.LifecycleStatus, cert.IssueStatus, cert.SyncStatus) {
	if old.Deleted || old.Status == "deleted" {
		return cert.LifecycleDeleted, cert.IssueIdle, cert.SyncSynced
	}
	syncStatus := cert.SyncStatus(opts.syncStatus)
	if syncStatus == "" {
		syncStatus = cert.SyncSynced
	}
	// 迁移工具只导当前仍在使用的有效证书，旧任务状态不再恢复为新 FSM 中间态。
	return cert.LifecycleActive, cert.IssueIdle, syncStatus
}

func upsertCertModel(store *infragorm.Store, model *infragorm.CertModel) error {
	return store.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "domain"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"lifecycle_status",
			"sync_status",
			"current_revision",
			"not_before",
			"not_after",
			"api_six_id",
			"fingerprint",
			"serial_number",
			"updated_at",
			"last_renew_at",
			"deleted",
			"deleted_at",
			"source",
			"last_synced_at",
			"sync_error",
			"issue_status",
			"last_issued_at",
			"challenge_zone",
			"sync_zones",
			"retry_count",
			"next_retry_at",
		}),
	}).Create(model).Error
}

func printSummary(stats migrationStats, opts migrationOptions) {
	fmt.Printf("decoded certificates: total=%d eligible=%d selected=%d skipped=%d deleted=%d missing_files=%d invalid_files=%d warnings=%d\n",
		stats.Total,
		stats.Eligible,
		stats.Selected,
		stats.Skipped,
		stats.Deleted,
		stats.MissingFiles,
		stats.InvalidFiles,
		stats.Warnings,
	)
	fmt.Printf("mode: %s limit=%d domains=%d sync_status=%s challenge_zone=%s sync_zones=%v\n",
		map[bool]string{true: "execute", false: "dry-run"}[opts.execute],
		opts.limit,
		len(opts.domains),
		opts.syncStatus,
		opts.challengeZone,
		opts.syncZones,
	)
}

func printPreview(items []migrationItem, opts migrationOptions) {
	limit := 20
	if opts.limit > 0 && opts.limit < limit {
		limit = opts.limit
	}
	printed := 0
	for _, item := range items {
		if !item.Selected {
			continue
		}
		fmt.Printf("migrate domain=%s old_status=%s revision=%d not_after=%d api_six_id=%s warnings=%d\n",
			item.Old.Domain,
			item.Old.Status,
			item.Revision,
			item.Metadata.NotAfter,
			item.APISIXID,
			len(item.Warnings),
		)
		fmt.Printf("  files cert=%s key=%s status=%s\n", item.CertPath, item.KeyPath, item.FileStatus)
		for _, warning := range item.Warnings {
			fmt.Printf("  warning: %s\n", warning)
		}
		printed++
		if printed >= limit {
			break
		}
	}
	if opts.limit <= 0 && printed == limit {
		fmt.Println("... preview truncated; use -limit N or -report report.csv for full detail")
	}
}

func writeReport(path string, items []migrationItem) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()
	if err := w.Write([]string{
		"domain",
		"selected",
		"eligible",
		"reason",
		"old_status",
		"revision",
		"not_before",
		"not_after",
		"api_six_id",
		"cert_path",
		"key_path",
		"file_status",
		"warnings",
	}); err != nil {
		return err
	}
	for _, item := range items {
		notBefore, notAfter := "", ""
		if item.Metadata != nil {
			notBefore = strconv.FormatInt(item.Metadata.NotBefore, 10)
			notAfter = strconv.FormatInt(item.Metadata.NotAfter, 10)
		}
		if err := w.Write([]string{
			item.Old.Domain,
			strconv.FormatBool(item.Selected),
			strconv.FormatBool(item.Eligible),
			item.Reason,
			item.Old.Status,
			strconv.FormatInt(item.Revision, 10),
			notBefore,
			notAfter,
			item.APISIXID,
			item.CertPath,
			item.KeyPath,
			item.FileStatus,
			strings.Join(item.Warnings, "; "),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func isInUseStatus(status string) bool {
	switch status {
	case "", "issued", "synced", "renewing", "failed":
		return true
	default:
		return false
	}
}

func certificateFilePaths(certDir, domain string) (string, string) {
	nestedDir := filepath.Join(certDir, domain)
	certPath := filepath.Join(nestedDir, domain+".cer")
	keyPath := filepath.Join(nestedDir, domain+".key")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath
	}
	return filepath.Join(certDir, domain+".cer"), filepath.Join(certDir, domain+".key")
}

func looksLikePrivateKey(keyPEM string) bool {
	for {
		block, rest := certPEMDecode([]byte(keyPEM))
		if block == "" {
			return false
		}
		if strings.Contains(block, "PRIVATE KEY") {
			return true
		}
		keyPEM = string(rest)
	}
}

func certPEMDecode(data []byte) (string, []byte) {
	start := bytes.Index(data, []byte("-----BEGIN "))
	if start < 0 {
		return "", nil
	}
	end := bytes.Index(data[start:], []byte("-----END "))
	if end < 0 {
		return "", nil
	}
	headerEnd := bytes.IndexByte(data[start:], '\n')
	if headerEnd < 0 {
		return "", nil
	}
	header := string(data[start+len("-----BEGIN ") : start+headerEnd])
	nextStart := start + end + len("-----END ")
	nextLine := bytes.IndexByte(data[nextStart:], '\n')
	if nextLine < 0 {
		return header, nil
	}
	return header, data[nextStart+nextLine+1:]
}

func normalizedRevision(old Certificate) int64 {
	if old.Revision > 0 {
		return old.Revision
	}
	return 1
}

func normalizedAPISIXID(old Certificate) string {
	if old.APISIXID != "" {
		return old.APISIXID
	}
	return cert.NormalizeAPISIXID(old.Domain)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stringSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

func toJSONArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	escaped := make([]string, 0, len(arr))
	for _, item := range arr {
		escaped = append(escaped, fmt.Sprintf("%q", item))
	}
	return "[" + strings.Join(escaped, ",") + "]"
}
