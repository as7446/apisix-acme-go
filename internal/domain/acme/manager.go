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
	accountRepo cert.AccountRepository
	httpStore   *HTTPChallengeStore
	clientInit  func(email string) (*lego.Client, error)
}

// NewManager 创建 ACME 管理器
func NewManager(cfg *config.Config, accountRepo cert.AccountRepository, httpStore *HTTPChallengeStore) *Manager {
	m := &Manager{
		cfg:         cfg,
		accountRepo: accountRepo,
		httpStore:   httpStore,
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
			if err := setEnvFromConfig(k, v); err != nil {
				return nil, fmt.Errorf("设置 DNS Provider 环境变量失败（%s）：%w", k, err)
			}
		}
		provider, err := newDNSChallengeProviderByName(m.cfg.AcmeDNSProvider)
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

// ObtainCertificate 纯 ACME 证书获取（不操作 APISIX，不写 DB）
// 返回证书 PEM、私钥 PEM、notBefore、notAfter
// 由 Issuer 调用，用于签发器和续期器的核心 ACME 操作
func (m *Manager) ObtainCertificate(domain, email string) (certPEM, keyPEM string, notBefore, notAfter int64, err error) {
	if email == "" {
		email = m.cfg.DefaultEmail
	}
	if email == "" {
		return "", "", 0, 0, fmt.Errorf("邮箱为空")
	}

	// 检查是否是通配符证书
	isWildcard := strings.HasPrefix(domain, "*.")
	if isWildcard && m.cfg.AcmeDNSProvider == "" {
		return "", "", 0, 0, fmt.Errorf("通配符证书（%s）必须使用 DNS-01 验证，请配置 acme_dns_provider", domain)
	}

	// 初始化 ACME 客户端
	client, err := m.clientInit(email)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("初始化 ACME 客户端失败：%w", err)
	}

	// HTTP-01 验证路由由 Controller FSM 通过 Agent 任务管理。

	// 构建证书请求
	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	if isWildcard {
		logger.Log.Info("申请通配符证书（使用 DNS-01 验证）", "domain", domain)
	} else {
		logger.Log.Info("申请证书", "domain", domain)
	}

	// 获取证书
	certRes, err := client.Certificate.Obtain(req)
	if err != nil {
		errMsg := fmt.Sprintf("申请证书失败：%v", err)
		if strings.Contains(err.Error(), "invalid character '<'") {
			errMsg += "（DNS Provider API 返回了 HTML 而非 JSON，可能是 API Token/Key 无效或配置错误）"
		}
		return "", "", 0, 0, fmt.Errorf("%s", errMsg)
	}

	// 解析证书获取有效期
	block, _ := pem.Decode([]byte(certRes.Certificate))
	if block == nil {
		return "", "", 0, 0, fmt.Errorf("解析证书 PEM 失败")
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("解析证书失败：%w", err)
	}

	logger.Log.Info("证书获取成功", "domain", domain,
		"not_before", certX509.NotBefore.Format("2006-01-02"),
		"not_after", certX509.NotAfter.Format("2006-01-02"))

	return string(certRes.Certificate),
		string(certRes.PrivateKey),
		certX509.NotBefore.Unix(),
		certX509.NotAfter.Unix(),
		nil
}

func setEnvFromConfig(k, v string) error {
	if strings.TrimSpace(k) == "" {
		return fmt.Errorf("环境变量名为空")
	}
	return os.Setenv(k, v)
}
