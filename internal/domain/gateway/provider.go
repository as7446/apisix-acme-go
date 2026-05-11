package gateway

import "context"

// SSLCert SSL 证书
type SSLCert struct {
	Domain string
	SNIs   []string
	Cert   string
	Key    string
}

// GatewayProvider 网关提供者接口
type GatewayProvider interface {
	// CreateSSL 创建 SSL 证书
	CreateSSL(ctx context.Context, cert *SSLCert) error
	// UpdateSSL 更新 SSL 证书
	UpdateSSL(ctx context.Context, cert *SSLCert) error
	// DeleteSSL 删除 SSL 证书
	DeleteSSL(ctx context.Context, domain string) error
}
