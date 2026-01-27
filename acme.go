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

	// 2. 如果有有效缓存，直接覆盖 APISIX
	if hasCache && cached.NotAfter > now && !force {
		Log.Info("缓存证书覆盖 APISIX", "domain", domain, "not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02 15:04:05"))
		if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
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

	if cached, ok := m.certCache.Get(domain); ok && !force {
		// 如果缓存中有有效证书且不是强制申请，使用缓存
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
		certRes, err := client.Certificate.Obtain(req)
		if err != nil {
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

	apisixID := domain
	if err := m.apisix.UpsertCertificate(apisixID, []string{domain}, certPEM, keyPEM, notAfter); err != nil {
		Log.Error("APISIX 上传证书失败", "domain", domain, "cert_path", m.certCache.GetCertPath(domain), "error", err)
		return nil, fmt.Errorf("APISIX 上传证书失败：%w", err)
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
	}
	if hasLocalMeta {
		cert.CreatedAt = localMeta.CreatedAt
	}
	if err := m.store.Upsert(cert); err != nil {
		return nil, fmt.Errorf("保存证书元数据失败：%w", err)
	}
	Log.Info("证书申请完成", "domain", domain, "fingerprint", fingerprint)
	return cert, nil
}

func (m *AcmeManager) RenewAll() {
	list, err := m.store.FindNeedRenew(m.cfg.RenewBeforeDays)
	if err != nil {
		Log.Error("查询需要续期的证书失败", "error", err)
		return
	}

	now := time.Now().Unix()

	for _, cert := range list {
		// 尝试锁定续期
		locked, err := m.store.LockRenew(cert.Domain)
		if err != nil {
			Log.Error("锁定续期失败", "domain", cert.Domain, "error", err)
			continue
		}
		if !locked {
			Log.Info("证书续期已被锁定，跳过", "domain", cert.Domain)
			continue
		}

		// 确保解锁
		defer func(domain string) {
			if err := m.store.UnlockRenew(domain); err != nil {
				Log.Error("解锁续期失败", "domain", domain, "error", err)
			}
		}(cert.Domain)

		renewThreshold := now + int64(m.cfg.RenewBeforeDays*24*int(time.Hour/time.Second))
		// 1. 检查缓存
		cached, hasCache := m.certCache.Get(cert.Domain)
		if hasCache && cached.NotAfter > now {
			// 如果缓存证书在续期阈值内，需要续期
			if cached.NotAfter <= renewThreshold {
				Log.Info("续期任务：缓存证书即将到期，执行续期", "days", m.cfg.RenewBeforeDays, "domain", cert.Domain)
			} else {
				if err := m.apisix.UpsertCertificate(cert.Domain, []string{cert.Domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
					Log.Error("续期上传缓存证书到 APISIX 失败", "domain", cert.Domain, "error", err)
				} else {
					// 更新 fingerprint 和 serial number
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
					continue
				}
			}
		}

		// 2. 判断是否需要续期
		needRenew := cert.NotAfter <= renewThreshold

		// 3. 如果需要续期，执行续期操作
		if needRenew {
			Log.Info("开始续期证书", "domain", cert.Domain)
			newCert, err := m.RequestCertificate(cert.Domain, "", false)
			if err != nil {
				Log.Error("续期证书失败", "domain", cert.Domain, "error", err)
			} else {
				// 更新续期时间
				newCert.LastRenewAt = now
				if err := m.store.Upsert(newCert); err != nil {
					Log.Error("更新续期时间失败", "domain", cert.Domain, "error", err)
				}
			}
		}
	}
}

func setEnvIfNotExists(k, v string) error {
	if _, ok := os.LookupEnv(k); ok {
		return nil
	}
	return os.Setenv(k, v)
}
