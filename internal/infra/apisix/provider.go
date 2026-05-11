package apisix

import (
	"context"

	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/domain/gateway"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
)

// Provider APISIX 网关提供者
type Provider struct {
	client *acme.ApisixClient
}

// NewProvider 创建 APISIX Provider
func NewProvider(cfg *config.Config) *Provider {
	return &Provider{
		client: acme.NewApisixClient(cfg),
	}
}

// CreateSSL 创建 SSL 证书
func (p *Provider) CreateSSL(ctx context.Context, cert *gateway.SSLCert) error {
	return p.client.UpsertCertificate(cert.Domain, cert.SNIs, cert.Cert, cert.Key, 0, nil)
}

// UpdateSSL 更新 SSL 证书
func (p *Provider) UpdateSSL(ctx context.Context, cert *gateway.SSLCert) error {
	// APISIX 更新其实就是删除再创建
	if err := p.client.DeleteCertificate(cert.Domain); err != nil {
		// 忽略删除错误，继续创建
	}
	return p.client.UpsertCertificate(cert.Domain, cert.SNIs, cert.Cert, cert.Key, 0, nil)
}

// DeleteSSL 删除 SSL 证书
func (p *Provider) DeleteSSL(ctx context.Context, domain string) error {
	return p.client.DeleteCertificate(domain)
}
