package main

import (
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	stormPath      string
	configPath     string
	certDir        string
	execute        bool
	includeDeleted bool
	challengeZone  string
	syncZones      []string
	source         string
}

func main() {
	opts := migrationOptions{}
	var syncZones string
	flag.StringVar(&opts.stormPath, "storm-db", "", "old Storm/BoltDB cert metadata path, e.g. /Users/hammer/Downloads/certs.db")
	flag.StringVar(&opts.configPath, "config", "config.controller.example.yml", "controller config path with MySQL DSN")
	flag.StringVar(&opts.certDir, "cert-dir", "", "old local cert root dir, e.g. /path/to/apisix_acme/out")
	flag.BoolVar(&opts.execute, "execute", false, "write to MySQL; default is dry-run")
	flag.BoolVar(&opts.includeDeleted, "include-deleted", false, "also migrate deleted old records")
	flag.StringVar(&opts.challengeZone, "challenge-zone", "", "default challenge_zone for migrated active certs")
	flag.StringVar(&syncZones, "sync-zones", "", "default sync_zones for migrated active certs, comma-separated; empty means all online agents")
	flag.StringVar(&opts.source, "source", string(cert.CertSourceManaged), "cert source: managed or external")
	flag.Parse()

	if opts.stormPath == "" {
		log.Fatal("-storm-db is required")
	}
	if opts.execute && opts.certDir == "" {
		log.Fatal("-cert-dir is required in execute mode")
	}
	opts.syncZones = splitCSV(syncZones)

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
	var candidateCount, skippedCount, deletedCount int
	for _, r := range records {
		if r.Deleted {
			deletedCount++
		}
		if shouldMigrateRecord(r, now) {
			candidateCount++
		} else {
			skippedCount++
		}
	}
	fmt.Printf("decoded certificates: total=%d candidates=%d skipped=%d deleted=%d\n", len(records), candidateCount, skippedCount, deletedCount)
	fmt.Printf("mode: %s\n", map[bool]string{true: "execute", false: "dry-run"}[opts.execute])

	if !opts.execute {
		printPreview(records, opts, now)
		fmt.Println("dry-run only. add -execute to write MySQL.")
		return
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

	var migrated, skipped int
	for _, old := range records {
		if !shouldMigrateRecord(old, now) {
			skipped++
			continue
		}
		model := toCertModel(old, opts)
		if err := upsertCertModel(store, model); err != nil {
			log.Fatalf("migrate %s: %v", old.Domain, err)
		}

		certPEM, keyPEM, err := readCertificateFiles(opts.certDir, old.Domain)
		if err != nil {
			log.Fatalf("read cert files for %s: %v", old.Domain, err)
		}
		if err := certRepo.ImportCertContent(old.Domain, int64(model.CurrentRevision), certPEM, keyPEM); err != nil {
			log.Fatalf("import cert content for %s: %v", old.Domain, err)
		}

		migrated++
	}

	fmt.Printf("migration finished: migrated=%d skipped=%d\n", migrated, skipped)
	fmt.Println("note: only non-deleted, unexpired, in-use certificates were migrated.")
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
				if c.Domain == "" || c.Fingerprint == "" {
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

func toCertModel(old Certificate, opts migrationOptions) *infragorm.CertModel {
	now := uint64(time.Now().Unix())
	revision := old.Revision
	if revision <= 0 {
		revision = 1
	}
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

	lifecycleStatus, issueStatus, syncStatus := mapOldStatus(old)
	apiSixID := old.APISIXID
	if apiSixID == "" {
		apiSixID = cert.NormalizeAPISIXID(old.Domain)
	}
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
		CurrentRevision: uint(revision),
		NotBefore:       uint64(old.NotBefore),
		NotAfter:        uint64(old.NotAfter),
		APISIXID:        apiSixID,
		Fingerprint:     old.Fingerprint,
		SerialNumber:    old.SerialNumber,
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

func mapOldStatus(old Certificate) (cert.LifecycleStatus, cert.IssueStatus, cert.SyncStatus) {
	if old.Deleted || old.Status == "deleted" {
		return cert.LifecycleDeleted, cert.IssueIdle, cert.SyncSynced
	}
	// 迁移工具只导当前仍在使用的有效证书，旧任务状态不再恢复为新 FSM 中间态。
	return cert.LifecycleActive, cert.IssueIdle, cert.SyncSynced
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

func printPreview(records []Certificate, opts migrationOptions, now int64) {
	limit := len(records)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		old := records[i]
		if !shouldMigrateRecord(old, now) {
			fmt.Printf("skip domain=%s old_status=%s reason=%s\n", old.Domain, old.Status, skipReason(old, now))
			continue
		}
		lifecycleStatus, issueStatus, syncStatus := mapOldStatus(old)
		certPath, keyPath := certificateFilePaths(opts.certDir, old.Domain)
		fileStatus := "cert-dir not set"
		if opts.certDir != "" {
			if _, err := os.Stat(certPath); err == nil {
				if _, err := os.Stat(keyPath); err == nil {
					fileStatus = "files ok"
				} else {
					fileStatus = "key missing"
				}
			} else {
				fileStatus = "cert missing"
			}
		}
		fmt.Printf("migrate domain=%s old_status=%s lifecycle=%s issue=%s sync=%s revision=%d not_after=%d challenge_zone=%s sync_zones=%v\n",
			old.Domain,
			old.Status,
			lifecycleStatus,
			issueStatus,
			syncStatus,
			maxInt64(old.Revision, 1),
			old.NotAfter,
			opts.challengeZone,
			opts.syncZones,
		)
		fmt.Printf("  files cert=%s key=%s status=%s\n", certPath, keyPath, fileStatus)
	}
	if len(records) > limit {
		fmt.Printf("... %d more records\n", len(records)-limit)
	}
}

func shouldMigrateRecord(old Certificate, now int64) bool {
	if old.Deleted {
		return false
	}
	if old.Domain == "" || old.Fingerprint == "" {
		return false
	}
	if old.NotAfter <= now {
		return false
	}
	return isInUseStatus(old.Status)
}

func skipReason(old Certificate, now int64) string {
	switch {
	case old.Deleted:
		return "deleted"
	case old.Domain == "":
		return "empty domain"
	case old.Fingerprint == "":
		return "missing fingerprint"
	case old.NotAfter <= now:
		return "expired"
	case !isInUseStatus(old.Status):
		return "status not in use"
	default:
		return "filtered"
	}
}

func isInUseStatus(status string) bool {
	switch status {
	case "", "issued", "synced", "renewing", "failed":
		return true
	default:
		return false
	}
}

func readCertificateFiles(certDir, domain string) (string, string, error) {
	certPath, keyPath := certificateFilePaths(certDir, domain)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", err
	}
	return string(certPEM), string(keyPEM), nil
}

func certificateFilePaths(certDir, domain string) (string, string) {
	if certDir == "" {
		return "", ""
	}
	nestedDir := filepath.Join(certDir, domain)
	certPath := filepath.Join(nestedDir, domain+".cer")
	keyPath := filepath.Join(nestedDir, domain+".key")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath
	}
	return filepath.Join(certDir, domain+".cer"), filepath.Join(certDir, domain+".key")
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

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
