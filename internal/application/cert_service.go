package application

import (
	"context"
	"errors"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/domain/gateway"
)

// ErrCertNotFound 证书未找到
var ErrCertNotFound = errors.New("certificate not found")

// CertInfoResult 证书信息结果
type CertInfoResult struct {
	Domain       string   `json:"domain"`
	SNIs         []string `json:"snis"`
	NotBefore    int64    `json:"not_before"`
	NotAfter     int64    `json:"not_after"`
	APISIXID     string   `json:"apisix_id"`
	Fingerprint  string   `json:"fingerprint"`
	SerialNumber string   `json:"serial_number"`
	Deleted      bool     `json:"deleted"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
}

// CertService 证书应用服务
type CertService struct {
	certRepo cert.CertRepository
	gateway  gateway.GatewayProvider
}

// NewCertService 创建 CertService
func NewCertService(certRepo cert.CertRepository, gatewayProvider gateway.GatewayProvider) *CertService {
	return &CertService{
		certRepo: certRepo,
		gateway:  gatewayProvider,
	}
}

// GetInfo 获取证书信息
func (s *CertService) GetInfo(ctx context.Context, domain string) (*CertInfoResult, error) {
	c, ok := s.certRepo.GetWithDeleted(domain)
	if !ok {
		return nil, ErrCertNotFound
	}
	return &CertInfoResult{
		Domain:       c.Domain,
		SNIs:         c.SNIs,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		APISIXID:     c.APISIXID,
		Fingerprint:  c.Fingerprint,
		SerialNumber: c.SerialNumber,
		Deleted:      c.Deleted,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}, nil
}

// Delete 删除证书
func (s *CertService) Delete(ctx context.Context, domain string) error {
	c, ok := s.certRepo.GetWithDeleted(domain)
	if !ok {
		return ErrCertNotFound
	}
	if c.Deleted {
		return nil
	}

	// 删除网关上的证书
	if err := s.gateway.DeleteSSL(ctx, domain); err != nil {
		return err
	}

	// 标记为删除
	return s.certRepo.MarkDeleted(domain)
}
