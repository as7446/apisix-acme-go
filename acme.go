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

func (m *AcmeManager) RequestCertificate(domain string, email string) (*CertMeta, error) {
	if email == "" {
		email = m.cfg.DefaultEmail
	}
	if email == "" {
		return nil, fmt.Errorf("邮箱为空")
	}

	var certPEM, keyPEM string
	var notBefore, notAfter int64

	if cached, ok := m.certCache.Get(domain); ok {
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
	for _, meta := range list {
		if !m.NeedRenew(meta) {
			continue
		}
		m.logger.Printf("开始续期证书：域名=%s", meta.Domain)
		if _, err := m.RequestCertificate(meta.Domain, ""); err != nil {
			m.logger.Printf("续期证书失败：域名=%s, 错误=%v（证书可能已缓存，可手动重试）", meta.Domain, err)
		}
	}
}

func setEnvIfNotExists(k, v string) error {
	if _, ok := os.LookupEnv(k); ok {
		return nil
	}
	return os.Setenv(k, v)
}
