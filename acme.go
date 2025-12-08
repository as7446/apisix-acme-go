package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	store      *FileCertStore
	certCache  *CertCache
	httpStore  *HTTPChallengeStore
	apisix     *ApisixClient
	logger     Logger
	clientInit func(email string) (*lego.Client, error)
}

func NewAcmeManager(cfg *Config, store *FileCertStore, certCache *CertCache, httpStore *HTTPChallengeStore, apiClient *ApisixClient, logger Logger) (*AcmeManager, error) {
	m := &AcmeManager{
		cfg:       cfg,
		store:     store,
		certCache: certCache,
		httpStore: httpStore,
		apisix:    apiClient,
		logger:    logger,
	}
	m.clientInit = m.defaultClientInit
	return m, nil
}

func (m *AcmeManager) defaultClientInit(email string) (*lego.Client, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	user := &AcmeUser{Email: email, key: privateKey}
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
		m.logger.Printf("DNS-01 Provider 已启用：%s", m.cfg.AcmeDNSProvider)
	}

	httpProvider := &HTTPChallengeProvider{store: m.httpStore}
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return nil, fmt.Errorf("设置 HTTP-01 Provider 失败：%w", err)
	}

	_, _ = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})

	return client, nil
}

// CheckAPISIXCertificate 检查 APISIX 中的证书是否存在以及是否过期
func (m *AcmeManager) CheckAPISIXCertificate(domain string) (exists bool, notAfter int64, err error) {
	apisixID := domain
	sslObj, err := m.apisix.GetCertificate(apisixID)
	if err != nil {
		return false, 0, fmt.Errorf("查询 APISIX 证书失败：%w", err)
	}
	if sslObj == nil {
		return false, 0, nil // 证书不存在
	}

	// 解析证书获取过期时间
	if sslObj.Cert == "" {
		return true, 0, nil // 证书存在但无法解析
	}
	block, _ := pem.Decode([]byte(sslObj.Cert))
	if block == nil {
		return true, 0, nil // 证书存在但格式错误
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, 0, nil // 证书存在但解析失败
	}
	return true, cert.NotAfter.Unix(), nil
}

// RequestCertificate 申请或更新证书
func (m *AcmeManager) RequestCertificate(domain string, email string, force bool) (*CertMeta, error) {
	if email == "" {
		email = m.cfg.DefaultEmail
	}
	if email == "" {
		return nil, fmt.Errorf("邮箱为空")
	}

	// 1. 检查本地元数据
	localMeta, hasLocalMeta := m.store.Get(domain)
	now := time.Now().Unix()

	// 2. 检查 APISIX 中的证书状态
	apisixExists, apisixNotAfter, err := m.CheckAPISIXCertificate(domain)
	if err != nil {
		m.logger.Printf("检查 APISIX 证书状态失败：域名=%s, 错误=%v，将继续处理", domain, err)
	}

	// 3. 判断是否需要申请新证书
	needNewCert := force
	if !needNewCert {
		// 如果 APISIX 中证书不存在，需要申请
		if !apisixExists {
			m.logger.Printf("APISIX 中证书不存在，需要申请：域名=%s", domain)
			needNewCert = true
		} else if apisixNotAfter > 0 {
			// 检查 APISIX 中的证书是否即将过期（提前30天）
			if apisixNotAfter-now <= int64(30*24*time.Hour/time.Second) {
				m.logger.Printf("APISIX 中证书即将过期，需要续期：域名=%s, 过期时间=%s", domain, time.Unix(apisixNotAfter, 0).Format("2006-01-02 15:04:05"))
				needNewCert = true
			}
		}
		// 如果本地有元数据但证书已过期，需要申请
		if hasLocalMeta && localMeta.NotAfter <= now {
			m.logger.Printf("本地证书已过期，需要申请：域名=%s", domain)
			needNewCert = true
		}
	}

	// 4. 如果不需要新证书，尝试从缓存或 APISIX 同步
	if !needNewCert {
		// 如果本地有有效证书，直接使用
		if hasLocalMeta && localMeta.NotAfter > now {
			// 检查缓存中是否有证书文件
			if cached, ok := m.certCache.Get(domain); ok {
				// 如果 APISIX 中证书不存在，需要上传
				if !apisixExists {
					m.logger.Printf("本地证书存在但 APISIX 中不存在，上传证书：域名=%s", domain)
					if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
						return nil, fmt.Errorf("上传证书到 APISIX 失败：%w", err)
					}
					// 更新元数据
					localMeta.UpdatedAt = now
					if err := m.store.Upsert(localMeta); err != nil {
						m.logger.Printf("更新证书元数据失败：%v", err)
					}
					return localMeta, nil
				}
				// 如果 APISIX 中证书存在且有效，直接返回
				if apisixExists && apisixNotAfter > now {
					m.logger.Printf("证书已存在且有效，跳过申请：域名=%s", domain)
					return localMeta, nil
				}
			}
		}
	}

	// 5. 需要申请新证书
	var certPEM, keyPEM string
	var notBefore, notAfter int64

	if cached, ok := m.certCache.Get(domain); ok && !force {
		// 如果缓存中有有效证书且不是强制申请，使用缓存
		m.logger.Printf("使用缓存的证书：域名=%s", domain)
		certPEM = cached.CertPEM
		keyPEM = cached.KeyPEM
		notBefore = cached.NotBefore
		notAfter = cached.NotAfter
	} else {
		routeCleanup := func() {}
		if m.cfg.ChallengeRoute.Enable {
			if err := m.apisix.EnsureChallengeRoute(m.cfg); err != nil {
				return nil, fmt.Errorf("创建验证路由失败：%w", err)
			}
			routeCleanup = func() {
				if err := m.apisix.DeleteChallengeRoute(m.cfg); err != nil {
					m.logger.Printf("删除验证路由失败：%v", err)
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
			m.logger.Printf("开始申请通配符证书：域名=%s（使用 DNS-01 验证）", domain)
		} else {
			m.logger.Printf("开始申请证书：域名=%s", domain)
		}
		certRes, err := client.Certificate.Obtain(req)
		if err != nil {
			errMsg := fmt.Sprintf("申请证书失败：%w", err)
			if strings.Contains(err.Error(), "invalid character '<'") {
				errMsg += "（DNS Provider API 返回了 HTML 而非 JSON，可能是 API Token/Key 无效或配置错误）"
			}
			return nil, fmt.Errorf(errMsg)
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

		// 保存到缓存（即使后续 APISIX 上传失败，证书也已缓存）
		if err := m.certCache.Put(domain, certPEM, keyPEM, notBefore, notAfter); err != nil {
			m.logger.Printf("保存证书到缓存失败：%v", err)
		}
		m.logger.Printf("证书申请成功：域名=%s, 有效期至=%s", domain, time.Unix(notAfter, 0).Format("2006-01-02 15:04:05"))
	}

	apisixID := domain
	if err := m.apisix.UpsertCertificate(apisixID, []string{domain}, certPEM, keyPEM, notAfter); err != nil {
		m.logger.Printf("APISIX 上传证书失败：域名=%s, 证书已缓存至=%s/%s, 下次请求将自动重试",
			domain, m.certCache.GetCertPath(domain), m.certCache.GetKeyPath(domain))
		return nil, fmt.Errorf("APISIX 上传证书失败：%w", err)
	}

	normalizedAPISIXID := strings.ReplaceAll(domain, "*.", "wildcard.")
	meta := &CertMeta{
		Domain:    domain,
		SNIs:      []string{domain},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		APISIXID:  normalizedAPISIXID,
	}
	if err := m.store.Upsert(meta); err != nil {
		return nil, fmt.Errorf("保存证书元数据失败：%w", err)
	}
	m.logger.Printf("证书申请完成：域名=%s", domain)
	return meta, nil
}

// NeedRenew 判断证书是否需要续期（提前 30 天）
func (m *AcmeManager) NeedRenew(meta *CertMeta) bool {
	now := time.Now().Unix()
	return meta.NotAfter-now <= int64(30*24*time.Hour/time.Second)
}

func (m *AcmeManager) RenewAll() {
	list := m.store.All()
	now := time.Now().Unix()

	for _, meta := range list {
		// 1. 检查本地证书是否需要续期
		needRenew := m.NeedRenew(meta)

		// 2. 检查 APISIX 中的证书状态
		apisixExists, apisixNotAfter, err := m.CheckAPISIXCertificate(meta.Domain)
		if err != nil {
			m.logger.Printf("检查 APISIX 证书状态失败：域名=%s, 错误=%v", meta.Domain, err)
		}

		// 3. 如果 APISIX 中证书不存在，需要上传
		if !apisixExists {
			m.logger.Printf("APISIX 中证书不存在，尝试上传本地证书：域名=%s", meta.Domain)
			if cached, ok := m.certCache.Get(meta.Domain); ok {
				// 检查缓存证书是否有效
				if cached.NotAfter > now {
					if err := m.apisix.UpsertCertificate(meta.Domain, []string{meta.Domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
						m.logger.Printf("上传证书到 APISIX 失败：域名=%s, 错误=%v", meta.Domain, err)
					} else {
						m.logger.Printf("证书已上传到 APISIX：域名=%s", meta.Domain)
						// 更新元数据
						meta.UpdatedAt = now
						if err := m.store.Upsert(meta); err != nil {
							m.logger.Printf("更新证书元数据失败：%v", err)
						}
						continue
					}
				} else {
					m.logger.Printf("本地缓存证书已过期，需要重新申请：域名=%s", meta.Domain)
					needRenew = true
				}
			} else {
				m.logger.Printf("本地缓存证书不存在，需要重新申请：域名=%s", meta.Domain)
				needRenew = true
			}
		} else if apisixNotAfter > 0 {
			// 4. 如果 APISIX 中证书即将过期，需要续期
			if apisixNotAfter-now <= int64(30*24*time.Hour/time.Second) {
				m.logger.Printf("APISIX 中证书即将过期，需要续期：域名=%s, 过期时间=%s", meta.Domain, time.Unix(apisixNotAfter, 0).Format("2006-01-02 15:04:05"))
				needRenew = true
			}
		}

		// 5. 如果需要续期，执行续期操作
		if needRenew {
			m.logger.Printf("开始续期证书：域名=%s", meta.Domain)
			if _, err := m.RequestCertificate(meta.Domain, "", false); err != nil {
				m.logger.Printf("续期证书失败：域名=%s, 错误=%v（证书可能已缓存，可手动重试）", meta.Domain, err)
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
