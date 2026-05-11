package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// HTTPChallengeStore HTTP-01 验证存储
type HTTPChallengeStore struct {
	mu    sync.RWMutex
	items map[string]string
}

func NewHTTPChallengeStore() *HTTPChallengeStore {
	return &HTTPChallengeStore{items: make(map[string]string)}
}

func (s *HTTPChallengeStore) Set(token, keyAuth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[token] = keyAuth
}

func (s *HTTPChallengeStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, token)
}

func (s *HTTPChallengeStore) Get(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.items[token]
	return val, ok
}

// HTTPChallengeProvider lego HTTP-01 provider
type HTTPChallengeProvider struct {
	store *HTTPChallengeStore
}

func (p *HTTPChallengeProvider) Present(domain, token, keyAuth string) error {
	if token == "" || keyAuth == "" {
		return fmt.Errorf("token 或 keyAuth 为空")
	}
	p.store.Set(token, keyAuth)
	return nil
}

func (p *HTTPChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	if token == "" {
		return nil
	}
	p.store.Delete(token)
	return nil
}

// AcmeUser ACME 用户
type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string                        { return u.Email }
func (u *AcmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Manager ACME 管理器
type Manager struct {
	cfg         *config.Config
	certRepo    cert.CertRepository
	accountRepo cert.AccountRepository
	certCache   cert.CertCache
	httpStore   *HTTPChallengeStore
	apisix      *ApisixClient
	clientInit  func(email string) (*lego.Client, error)
}

// NewManager 创建 ACME 管理器
func NewManager(cfg *config.Config, certRepo cert.CertRepository, accountRepo cert.AccountRepository, certCache cert.CertCache, httpStore *HTTPChallengeStore, apiClient *ApisixClient) *Manager {
	m := &Manager{
		cfg:         cfg,
		certRepo:    certRepo,
		accountRepo: accountRepo,
		certCache:   certCache,
		httpStore:   httpStore,
		apisix:      apiClient,
	}
	m.clientInit = m.defaultClientInit
	return m
}

func (m *Manager) defaultClientInit(email string) (*lego.Client, error) {
	var privateKey crypto.PrivateKey
	var reg *registration.Resource

	if m.accountRepo != nil {
		account, err := m.accountRepo.GetAccount(email)
		if err == nil && account != nil {
			logger.Log.Info("加载已有 ACME 账户", "email", email)
			block, _ := pem.Decode(account.PrivateKey)
			if block == nil {
				return nil, fmt.Errorf("解析账户私钥失败")
			}
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("解析账户私钥失败：%w", err)
			}
			if len(account.Registration) > 0 {
				reg = &registration.Resource{}
				if err := json.Unmarshal(account.Registration, reg); err != nil {
					logger.Log.Error("解析账户注册信息失败（将尝试重新注册）", "error", err)
					reg = nil
				}
			}
		}
	}

	if privateKey == nil {
		logger.Log.Info("创建新 ACME 账户", "email", email)
		key, err := rsa.GenerateKey(rand.Reader, config.RSAKeyBits)
		if err != nil {
			return nil, err
		}
		privateKey = key
	}

	user := &AcmeUser{Email: email, Registration: reg, key: privateKey}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = m.cfg.AcmeDirectoryURL
	cfg.HTTPClient.Timeout = time.Duration(m.cfg.HTTPTimeout) * time.Second
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	if m.cfg.AcmeDNSProvider != "" {
		for k, v := range m.cfg.AcmeDNSEnv {
			_ = setEnvIfNotExists(k, v)
		}
		provider, err := dns.NewDNSChallengeProviderByName(m.cfg.AcmeDNSProvider)
		if err != nil {
			return nil, fmt.Errorf("初始化 DNS Provider 失败（%s）：%w，请检查 acme_dns_provider 配置", m.cfg.AcmeDNSProvider, err)
		}
		if err := client.Challenge.SetDNS01Provider(provider); err != nil {
			return nil, fmt.Errorf("设置 DNS-01 Provider 失败：%w", err)
		}
		logger.Log.Info("DNS-01 Provider 已启用", "provider", m.cfg.AcmeDNSProvider)
	}

	httpProvider := &HTTPChallengeProvider{store: m.httpStore}
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return nil, fmt.Errorf("设置 HTTP-01 Provider 失败：%w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("用户注册失败：%w", err)
		}
		user.Registration = reg

		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

		regBytes, err := json.Marshal(reg)
		if err != nil {
			logger.Log.Error("序列化注册信息失败", "error", err)
		} else {
			account := &cert.AcmeAccount{
				Email:        email,
				PrivateKey:   keyPEM,
				Registration: regBytes,
			}
			if err := m.accountRepo.SaveAccount(account); err != nil {
				logger.Log.Error("保存 ACME 账户信息失败", "error", err)
			} else {
				logger.Log.Info("ACME 账户信息已保存", "email", email)
			}
		}
	}

	return client, nil
}

// CheckAPISIXCertificate 检查证书是否存在及过期时间
func (m *Manager) CheckAPISIXCertificate(domain string) (exists bool, notAfter int64, err error) {
	sslObj, err := m.apisix.GetCertificate(domain)
	if err != nil {
		return false, 0, fmt.Errorf("查询 APISIX 证书失败：%w", err)
	}
	if sslObj == nil {
		return false, 0, nil
	}
	if sslObj.Cert == "" {
		return true, 0, nil
	}
	block, _ := pem.Decode([]byte(sslObj.Cert))
	if block == nil {
		return true, 0, nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, 0, nil
	}
	return true, c.NotAfter.Unix(), nil
}

// RequestCertificate 申请或更新证书
func (m *Manager) RequestCertificate(domain string, email string, force bool) (*cert.Certificate, error) {
	if email == "" {
		email = m.cfg.DefaultEmail
	}
	if email == "" {
		return nil, fmt.Errorf("邮箱为空")
	}

	localMeta, hasLocalMeta := m.certRepo.Get(domain)
	now := time.Now().Unix()
	cached, hasCache := m.certCache.Get(domain)

	// 幂等检查
	if hasLocalMeta && localMeta.Renewing && !force {
		logger.Log.Info("证书续期中，跳过重复申请（幂等保护）", "domain", domain, "order_url", localMeta.AcmeOrderURL)
		return localMeta, nil
	}

	// 缓存覆盖
	if hasCache && cached.NotAfter > now && !force {
		logger.Log.Info("缓存证书覆盖 APISIX", "domain", domain, "not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02 15:04:05"))
		labels := map[string]string{"managed-by": m.cfg.ManagedByLabel}
		if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter, labels); err != nil {
			return nil, fmt.Errorf("缓存上传证书到 APISIX 失败：%w", err)
		}

		fingerprint, _ := cert.CalculateFingerprint(cached.CertPEM)
		serialNumber, _ := cert.CalculateSerialNumber(cached.CertPEM)

		certificate := &cert.Certificate{
			Domain:       domain,
			SNIs:         []string{domain},
			NotBefore:    cached.NotBefore,
			NotAfter:     cached.NotAfter,
			APISIXID:     cert.NormalizeAPISIXID(domain),
			Fingerprint:  fingerprint,
			SerialNumber: serialNumber,
		}
		if hasLocalMeta {
			certificate.CreatedAt = localMeta.CreatedAt
		}
		if err := m.certRepo.Upsert(certificate); err != nil {
			return nil, fmt.Errorf("保存证书元数据失败：%w", err)
		}
		logger.Log.Info("缓存证书覆盖 APISIX 完成", "domain", domain)
		return certificate, nil
	}

	// 需要申请新证书
	var certPEM, keyPEM string
	var notBefore, notAfter int64

	renewThreshold := now + int64(m.cfg.RenewBeforeDays*24*int(time.Hour/time.Second))
	if cached, ok := m.certCache.Get(domain); ok && !force && cached.NotAfter > renewThreshold {
		logger.Log.Info("使用缓存的证书", "domain", domain)
		certPEM = cached.CertPEM
		keyPEM = cached.KeyPEM
		notBefore = cached.NotBefore
		notAfter = cached.NotAfter
	} else {
		routeID := ""
		routeCleanup := func() {}
		if m.cfg.ChallengeRoute.Enable {
			var err error
			routeID, err = m.apisix.EnsureChallengeRoute(m.cfg, domain)
			if err != nil {
				return nil, fmt.Errorf("创建验证路由失败：%w", err)
			}
			routeCleanup = func() {
				if err := m.apisix.DeleteChallengeRoute(routeID); err != nil {
					logger.Log.Error("删除验证路由失败", "error", err)
				}
			}
		}
		defer routeCleanup()

		client, err := m.clientInit(email)
		if err != nil {
			return nil, fmt.Errorf("初始化 ACME 客户端失败：%w", err)
		}

		req := certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		}
		isWildcard := strings.HasPrefix(domain, "*.")
		if isWildcard {
			if m.cfg.AcmeDNSProvider == "" {
				return nil, fmt.Errorf("通配符证书（%s）必须使用 DNS-01 验证，请配置 acme_dns_provider", domain)
			}
			logger.Log.Info("开始申请通配符证书（使用 DNS-01 验证）", "domain", domain)
		} else {
			logger.Log.Info("开始申请证书", "domain", domain)
		}

		_ = m.certRepo.SetRenewing(domain, true, "")

		certRes, err := client.Certificate.Obtain(req)
		if err != nil {
			_ = m.certRepo.SetRenewing(domain, false, "")
			errMsg := fmt.Sprintf("申请证书失败：%v", err)
			if strings.Contains(err.Error(), "invalid character '<'") {
				errMsg += "（DNS Provider API 返回了 HTML 而非 JSON，可能是 API Token/Key 无效或配置错误）"
			}
			return nil, fmt.Errorf("%s", errMsg)
		}

		block, _ := pem.Decode(certRes.Certificate)
		if block == nil {
			return nil, fmt.Errorf("解析证书 PEM 失败")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败：%w", err)
		}

		notBefore = certificate.NotBefore.Unix()
		notAfter = certificate.NotAfter.Unix()
		certPEM = string(certRes.Certificate)
		keyPEM = string(certRes.PrivateKey)

		if err := m.certCache.Put(domain, certPEM, keyPEM, notBefore, notAfter); err != nil {
			logger.Log.Error("保存证书到缓存失败", "error", err)
		}
	}

	fingerprint, _ := cert.CalculateFingerprint(certPEM)
	serialNumber, _ := cert.CalculateSerialNumber(certPEM)

	certificate := &cert.Certificate{
		Domain:       domain,
		SNIs:         []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		APISIXID:     cert.NormalizeAPISIXID(domain),
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber,
		Status:       cert.CertStatusIssued,
		LastIssuedAt: now,
	}
	if hasLocalMeta {
		certificate.CreatedAt = localMeta.CreatedAt
	}
	if err := m.certRepo.Upsert(certificate); err != nil {
		return nil, fmt.Errorf("保存证书元数据失败：%w", err)
	}
	_ = m.certRepo.SetRenewing(domain, false, "")

	apisixID := domain
	revision := certificate.CurrentRevision
	if updated, ok := m.certRepo.Get(domain); ok {
		revision = updated.CurrentRevision
	}
	labels := map[string]string{
		"managed-by":      m.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", revision),
	}
	if err := m.apisix.UpsertCertificate(apisixID, []string{domain}, certPEM, keyPEM, notAfter, labels); err != nil {
		logger.Log.Error("APISIX 上传证书失败（证书已保存到数据库，sync 任务会重试）",
			"domain", domain, "error", err)
		_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, err.Error())
	}

	logger.Log.Info("证书申请完成", "domain", domain, "fingerprint", fingerprint)
	return certificate, nil
}

// RenewAll 续期所有需要续期的证书
func (m *Manager) RenewAll() {
	list, err := m.certRepo.FindNeedRenew(m.cfg.RenewBeforeDays)
	if err != nil {
		logger.Log.Error("查询需要续期的证书失败", "error", err)
		return
	}
	if len(list) == 0 {
		return
	}
	var certs []string
	for i := range list {
		certs = append(certs, list[i].Domain)
	}
	logger.Log.Info("检测到续期证书", "domains", strings.Join(certs, ","))

	now := time.Now().Unix()

	for _, c := range list {
		func(certificate *cert.Certificate) {
			locked, err := m.certRepo.LockRenew(certificate.Domain)
			if err != nil {
				logger.Log.Error("锁定续期失败", "domain", certificate.Domain, "error", err)
				return
			}
			if !locked {
				return
			}
			defer func() {
				if err := m.certRepo.UnlockRenew(certificate.Domain); err != nil {
					logger.Log.Error("解锁续期失败", "domain", certificate.Domain, "error", err)
				}
			}()

			renewThreshold := now + int64(m.cfg.RenewBeforeDays*24*int(time.Hour/time.Second))

			cached, hasCache := m.certCache.Get(certificate.Domain)
			if hasCache && cached.NotAfter > renewThreshold {
				logger.Log.Info("续期任务：缓存证书时间充足，同步到 APISIX", "domain", certificate.Domain,
					"not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02"))
				labels := map[string]string{
					"managed-by":      m.cfg.ManagedByLabel,
					"x-acme-revision": fmt.Sprintf("%d", certificate.CurrentRevision),
				}
				if err := m.apisix.UpsertCertificate(certificate.Domain, []string{certificate.Domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter, labels); err != nil {
					logger.Log.Error("续期同步缓存证书到 APISIX 失败", "domain", certificate.Domain, "error", err)
				} else {
					fingerprint, _ := cert.CalculateFingerprint(cached.CertPEM)
					serialNumber, _ := cert.CalculateSerialNumber(cached.CertPEM)
					certificate.NotBefore = cached.NotBefore
					certificate.NotAfter = cached.NotAfter
					certificate.Fingerprint = fingerprint
					certificate.SerialNumber = serialNumber
					certificate.LastRenewAt = now
					if err := m.certRepo.Upsert(certificate); err != nil {
						logger.Log.Error("续期更新元数据失败", "domain", certificate.Domain, "error", err)
					}
				}
				return
			}

			logger.Log.Info("开始续期证书（强制签发）", "domain", certificate.Domain,
				"not_after", time.Unix(certificate.NotAfter, 0).Format("2006-01-02"),
				"renew_before_days", m.cfg.RenewBeforeDays)
			newCert, err := m.RequestCertificate(certificate.Domain, "", true)
			if err != nil {
				logger.Log.Error("续期证书失败", "domain", certificate.Domain, "error", err)
			} else {
				newCert.LastRenewAt = now
				if err := m.certRepo.Upsert(newCert); err != nil {
					logger.Log.Error("更新续期时间失败", "domain", certificate.Domain, "error", err)
				}
			}
		}(c)
	}
}

func setEnvIfNotExists(k, v string) error {
	if _, ok := os.LookupEnv(k); ok {
		return nil
	}
	return os.Setenv(k, v)
}
