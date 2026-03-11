package main

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
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}

func (u *AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type AcmeManager struct {
	cfg        *Config
	store      *StormCertStore
	certCache  *CertCache
	httpStore  *HTTPChallengeStore
	apisix     *ApisixClient
	clientInit func(email string) (*lego.Client, error)
}

func NewAcmeManager(cfg *Config, store *StormCertStore, certCache *CertCache, httpStore *HTTPChallengeStore, apiClient *ApisixClient) (*AcmeManager, error) {
	m := &AcmeManager{
		cfg:       cfg,
		store:     store,
		certCache: certCache,
		httpStore: httpStore,
		apisix:    apiClient,
	}
	m.clientInit = m.defaultClientInit
	return m, nil
}

func (m *AcmeManager) defaultClientInit(email string) (*lego.Client, error) {
	var privateKey crypto.PrivateKey
	var reg *registration.Resource

	// 1. 尝试从存储中加载账户
	account, err := m.store.GetAccount(email)
	if err == nil {
		Log.Info("加载已有 ACME 账户", "email", email)
		// 解析私钥
		block, _ := pem.Decode(account.PrivateKey)
		if block == nil {
			return nil, fmt.Errorf("解析账户私钥失败")
		}
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析账户私钥失败：%w", err)
		}

		// 解析注册信息
		if len(account.Registration) > 0 {
			reg = &registration.Resource{}
			if err := json.Unmarshal(account.Registration, reg); err != nil {
				Log.Error("解析账户注册信息失败（将尝试重新注册）", "error", err)
				reg = nil
			}
		}
	}

	// 2. 如果没有已有账户或加载失败，创建新账户
	if privateKey == nil {
		Log.Info("创建新 ACME 账户", "email", email)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		privateKey = key
	}

	user := &AcmeUser{
		Email:        email,
		Registration: reg,
		key:          privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = m.cfg.AcmeDirectoryURL
	// 配置 HTTP 超时
	config.HTTPClient.Timeout = time.Duration(m.cfg.HTTPTimeout) * time.Second
	client, err := lego.NewClient(config)
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
		Log.Info("DNS-01 Provider 已启用", "provider", m.cfg.AcmeDNSProvider)
	}

	httpProvider := &HTTPChallengeProvider{store: m.httpStore}
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return nil, fmt.Errorf("设置 HTTP-01 Provider 失败：%w", err)
	}

	// 3. 如果是新用户或注册信息丢失，执行注册并保存
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("用户注册失败：%w", err)
		}
		user.Registration = reg

		// 保存账户信息
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

		regBytes, err := json.Marshal(reg)
		if err != nil {
			Log.Error("序列化注册信息失败", "error", err)
		} else {
			newAccount := &AcmeAccount{
				Email:        email,
				PrivateKey:   keyPEM,
				Registration: regBytes,
			}
			if err := m.store.SaveAccount(newAccount); err != nil {
				Log.Error("保存 ACME 账户信息失败", "error", err)
			} else {
				Log.Info("ACME 账户信息已保存", "email", email)
			}
		}
	}

	return client, nil
}

// CheckAPISIXCertificate 检查证书是否存在及过期时间
func (m *AcmeManager) CheckAPISIXCertificate(domain string) (exists bool, notAfter int64, err error) {
	apisixID := domain
	sslObj, err := m.apisix.GetCertificate(apisixID)
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
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, 0, nil
	}
	return true, cert.NotAfter.Unix(), nil
}

// RequestCertificate 申请或更新证书
func (m *AcmeManager) RequestCertificate(domain string, email string, force bool) (*Certificate, error) {
	if email == "" {
		email = m.cfg.DefaultEmail
	}
	if email == "" {
		return nil, fmt.Errorf("邮箱为空")
	}

	// 1. 检查本地元数据与缓存
	localMeta, hasLocalMeta := m.store.Get(domain)
	now := time.Now().Unix()
	cached, hasCache := m.certCache.Get(domain)

	// 幂等检查：如果正在续期中（Renewing=true 且未超时），直接跳过
	// 注：超时重置由 sync.reconcileCert 负责（1 小时锁超时）
	if hasLocalMeta && localMeta.Renewing && !force {
		Log.Info("证书续期中，跳过重复申请（幂等保护）", "domain", domain,
			"order_url", localMeta.AcmeOrderURL)
		return localMeta, nil
	}

	// 2. 如果有有效缓存，直接覆盖 APISIX
	if hasCache && cached.NotAfter > now && !force {
		Log.Info("缓存证书覆盖 APISIX", "domain", domain, "not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02 15:04:05"))
		managedLabels := map[string]string{"managed-by": m.cfg.ManagedByLabel}
		if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter, managedLabels); err != nil {
			return nil, fmt.Errorf("缓存上传证书到 APISIX 失败：%w", err)
		}

		// 计算 fingerprint 和 serial number
		fingerprint, err := CalculateFingerprint(cached.CertPEM)
		if err != nil {
			Log.Error("计算证书指纹失败", "error", err)
			fingerprint = ""
		}
		serialNumber, err := CalculateSerialNumber(cached.CertPEM)
		if err != nil {
			Log.Error("计算证书序列号失败", "error", err)
			serialNumber = ""
		}

		cert := &Certificate{
			Domain:       domain,
			SNIs:         []string{domain},
			NotBefore:    cached.NotBefore,
			NotAfter:     cached.NotAfter,
			APISIXID:     strings.ReplaceAll(domain, "*.", "wildcard."),
			Fingerprint:  fingerprint,
			SerialNumber: serialNumber,
		}
		if hasLocalMeta {
			cert.CreatedAt = localMeta.CreatedAt
		}
		if err := m.store.Upsert(cert); err != nil {
			return nil, fmt.Errorf("保存证书元数据失败：%w", err)
		}
		Log.Info("缓存证书覆盖 APISIX 完成", "domain", domain)
		return cert, nil
	}

	// 3. 判断是否需要申请新证书（仅依据本地元数据/force）
	needNewCert := force || !hasLocalMeta || localMeta.NotAfter <= now

	// 4. 本地元数据有效但无缓存时，强制申请新证书以补齐文件
	if !needNewCert && hasLocalMeta {
		Log.Info("本地元数据有效但缓存缺失，申请新证书以补齐文件", "domain", domain)
	}

	// 5. 需要申请新证书
	var certPEM, keyPEM string
	var notBefore, notAfter int64

	// 只有当缓存证书不在续期窗口（NotAfter 充足）时才直接使用缓存；
	// 若证书即将到期（needNewCert=true 或 NotAfter 在续期阈值内），必须走 ACME 签发。
	renewThreshold := now + int64(m.cfg.RenewBeforeDays*24*int(time.Hour/time.Second))
	if cached, ok := m.certCache.Get(domain); ok && !force && cached.NotAfter > renewThreshold {
		// 缓存证书充足（不在续期窗口内），直接使用
		Log.Info("使用缓存的证书", "domain", domain)
		certPEM = cached.CertPEM
		keyPEM = cached.KeyPEM
		notBefore = cached.NotBefore
		notAfter = cached.NotAfter
	} else {
		var routeID string
		routeCleanup := func() {}
		if m.cfg.ChallengeRoute.Enable {
			var err error
			routeID, err = m.apisix.EnsureChallengeRoute(m.cfg, domain)
			if err != nil {
				return nil, fmt.Errorf("创建验证路由失败：%w", err)
			}
			routeCleanup = func() {
				if err := m.apisix.DeleteChallengeRoute(routeID); err != nil {
					Log.Error("删除验证路由失败", "error", err)
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
		// 检查是否为通配符证书
		isWildcard := strings.HasPrefix(domain, "*.")
		if isWildcard {
			if m.cfg.AcmeDNSProvider == "" {
				return nil, fmt.Errorf("通配符证书（%s）必须使用 DNS-01 验证，请配置 acme_dns_provider", domain)
			}
			Log.Info("开始申请通配符证书（使用 DNS-01 验证）", "domain", domain)
		} else {
			Log.Info("开始申请证书", "domain", domain)
		}
		// 幂等保护：在发起 ACME 之前标记续期中，防止并发重复续期
		// 锁超时（1h）由 sync.reconcileCert 负责重置
		_ = m.store.SetRenewing(domain, true, "")

		certRes, err := client.Certificate.Obtain(req)
		if err != nil {
			// 申请失败：清除续期锁，让下次重试
			_ = m.store.SetRenewing(domain, false, "")
			errMsg := fmt.Sprintf("申请证书失败：%v", err)
			if strings.Contains(err.Error(), "invalid character '<'") {
				errMsg += "（DNS Provider API 返回了 HTML 而非 JSON，可能是 API Token/Key 无效或配置错误）"
			}
			return nil, fmt.Errorf("%s", errMsg)
		}

		// 解析证书有效期
		block, _ := pem.Decode(certRes.Certificate)
		if block == nil {
			return nil, fmt.Errorf("解析证书 PEM 失败")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败：%w", err)
		}

		notBefore = cert.NotBefore.Unix()
		notAfter = cert.NotAfter.Unix()
		certPEM = string(certRes.Certificate)
		keyPEM = string(certRes.PrivateKey)

		// 保存到缓存
		if err := m.certCache.Put(domain, certPEM, keyPEM, notBefore, notAfter); err != nil {
			Log.Error("保存证书到缓存失败", "error", err)
		}
		Log.Info("证书申请成功", "domain", domain, "not_after", time.Unix(notAfter, 0).Format("2006-01-02 15:04:05"))
	}

	// 计算 fingerprint 和 serial number
	fingerprint, err := CalculateFingerprint(certPEM)
	if err != nil {
		Log.Error("计算证书指纹失败", "error", err)
		fingerprint = ""
	}
	serialNumber, err := CalculateSerialNumber(certPEM)
	if err != nil {
		Log.Error("计算证书序列号失败", "error", err)
		serialNumber = ""
	}

	normalizedAPISIXID := normalizeAPISIXID(domain)
	cert := &Certificate{
		Domain:       domain,
		SNIs:         []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		APISIXID:     normalizedAPISIXID,
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber,
		Status:       CertStatusIssued,
		LastIssuedAt: now,
	}
	if hasLocalMeta {
		cert.CreatedAt = localMeta.CreatedAt
	}
	// 先保存到数据库（确保证书不丢失），同时清除续期锁
	if err := m.store.Upsert(cert); err != nil {
		return nil, fmt.Errorf("保存证书元数据失败：%w", err)
	}
	// 清除续期中标志和 OrderURL
	_ = m.store.SetRenewing(domain, false, "")
	Log.Info("证书元数据已保存到数据库", "domain", domain, "fingerprint", fingerprint, "revision", cert.Revision)

	// 再上传到 APISIX（携带 revision label；失败则由 sync 任务重试）
	apisixID := domain
	// 上传时从 DB 读取最新 revision（Upsert 已自增）
	revision := cert.Revision
	if updated, ok := m.store.Get(domain); ok {
		revision = updated.Revision
	}
	managedLabels := map[string]string{
		"managed-by":      m.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", revision),
	}
	if err := m.apisix.UpsertCertificate(apisixID, []string{domain}, certPEM, keyPEM, notAfter, managedLabels); err != nil {
		Log.Error("APISIX 上传证书失败（证书已保存到数据库，sync 任务会重试）",
			"domain", domain, "cert_path", m.certCache.GetCertPath(domain), "error", err)
		_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, err.Error())
		// 不返回错误，证书已安全保存
	}

	Log.Info("证书申请完成", "domain", domain, "fingerprint", fingerprint)
	return cert, nil
}

func (m *AcmeManager) RenewAll() {
	list, err := m.store.FindNeedRenew(m.cfg.RenewBeforeDays)
	if len(list) == 0 {
		return
	}
	certs := make([]string, len(list))
	for i := range list {
		certs = append(certs, list[i].Domain)
	}
	Log.Info("检测到续期证书：", certs)
	if err != nil {
		Log.Error("查询需要续期的证书失败", "error", err)
		return
	}

	now := time.Now().Unix()

	for _, cert := range list {
		// 每个证书在独立闭包中处理：确保续期锁在本次迭代结束后立即释放，
		// 而不是等整个 RenewAll 函数返回（defer 在循环内的经典问题）。
		func(cert *Certificate) {
			// 尝试锁定续期
			locked, err := m.store.LockRenew(cert.Domain)
			if err != nil {
				Log.Error("锁定续期失败", "domain", cert.Domain, "error", err)
				return
			}
			if !locked {
				Log.Info("证书续期已被锁定，跳过", "domain", cert.Domain)
				return
			}
			// 闭包返回时立即解锁（本次迭代结束即释放，不影响其他证书）
			defer func() {
				if err := m.store.UnlockRenew(cert.Domain); err != nil {
					Log.Error("解锁续期失败", "domain", cert.Domain, "error", err)
				}
			}()

			renewThreshold := now + int64(m.cfg.RenewBeforeDays*24*int(time.Hour/time.Second))

			// 1. 检查缓存：仅当缓存证书完全在续期窗口之外时才直接同步到 APISIX 并跳过续期
			cached, hasCache := m.certCache.Get(cert.Domain)
			if hasCache && cached.NotAfter > renewThreshold {
				// 缓存证书有效且不在续期窗口——同步到 APISIX 即可，无需重新签发
				Log.Info("续期任务：缓存证书充足，同步到 APISIX", "domain", cert.Domain,
					"not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02"))
				managedLabels := map[string]string{
					"managed-by":      m.cfg.ManagedByLabel,
					"x-acme-revision": fmt.Sprintf("%d", cert.Revision),
				}
				if err := m.apisix.UpsertCertificate(cert.Domain, []string{cert.Domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter, managedLabels); err != nil {
					Log.Error("续期同步缓存证书到 APISIX 失败", "domain", cert.Domain, "error", err)
				} else {
					fingerprint, _ := CalculateFingerprint(cached.CertPEM)
					serialNumber, _ := CalculateSerialNumber(cached.CertPEM)
					cert.NotBefore = cached.NotBefore
					cert.NotAfter = cached.NotAfter
					cert.Fingerprint = fingerprint
					cert.SerialNumber = serialNumber
					cert.LastRenewAt = now
					if err := m.store.Upsert(cert); err != nil {
						Log.Error("续期更新元数据失败", "domain", cert.Domain, "error", err)
					}
				}
				return
			}

			// 2. 缓存不存在、已过期或在续期窗口内——强制重新签发新证书
			// 使用 force=true 跳过 RequestCertificate 内部的缓存复用判断，确保真正向 ACME 申请
			Log.Info("开始续期证书（强制签发）", "domain", cert.Domain,
				"not_after", time.Unix(cert.NotAfter, 0).Format("2006-01-02"),
				"renew_before_days", m.cfg.RenewBeforeDays)
			newCert, err := m.RequestCertificate(cert.Domain, "", true)
			if err != nil {
				Log.Error("续期证书失败", "domain", cert.Domain, "error", err)
			} else {
				newCert.LastRenewAt = now
				if err := m.store.Upsert(newCert); err != nil {
					Log.Error("更新续期时间失败", "domain", cert.Domain, "error", err)
				}
			}
		}(cert)
	}
}

func setEnvIfNotExists(k, v string) error {
	if _, ok := os.LookupEnv(k); ok {
		return nil
	}
	return os.Setenv(k, v)
}
