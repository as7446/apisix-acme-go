package handler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
)

// DNSCheckResult 描述新建证书前的 DNS 可用性检查结果。
type DNSCheckResult struct {
	Domain           string   `json:"domain"`
	NormalizedDomain string   `json:"normalized_domain"`
	Wildcard         bool     `json:"wildcard"`
	CheckType        string   `json:"check_type"`
	OK               bool     `json:"ok"`
	Message          string   `json:"message"`
	Records          []string `json:"records,omitempty"`
	Zone             string   `json:"zone,omitempty"`
	ChallengeName    string   `json:"challenge_name,omitempty"`
}

// DNSHandler 提供轻量 DNS 诊断接口，供 Web UI 在创建证书前提示使用。
type DNSHandler struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSHandler() *DNSHandler {
	return &DNSHandler{
		resolver: net.DefaultResolver,
		timeout:  5 * time.Second,
	}
}

func (h *DNSHandler) Check(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		response.BadRequest(c, fmt.Errorf("domain 不能为空"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
	defer cancel()

	response.Success(c, h.check(ctx, domain))
}

func (h *DNSHandler) check(ctx context.Context, domain string) DNSCheckResult {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	wildcard := strings.HasPrefix(normalized, "*.")
	if wildcard {
		baseDomain := strings.TrimPrefix(normalized, "*.")
		zone, records, err := h.lookupZone(ctx, baseDomain)
		result := DNSCheckResult{
			Domain:           domain,
			NormalizedDomain: baseDomain,
			Wildcard:         true,
			CheckType:        "dns01_zone",
			OK:               err == nil,
			Records:          records,
			Zone:             zone,
			ChallengeName:    "_acme-challenge." + baseDomain,
		}
		if err != nil {
			result.Message = "未找到可解析的 DNS Zone；请确认域名已托管到 DNS 服务商，并且 DNSPod 凭据有该 Zone 权限"
			return result
		}
		result.Message = "通配符证书将使用 DNS-01；已找到 DNS Zone，签发时会写入 challenge TXT 记录"
		return result
	}

	records, err := h.lookupDomain(ctx, normalized)
	result := DNSCheckResult{
		Domain:           domain,
		NormalizedDomain: normalized,
		Wildcard:         false,
		CheckType:        "http01_domain",
		OK:               err == nil,
		Records:          records,
	}
	if err != nil {
		result.Message = "域名 A/AAAA/CNAME 解析未生效；HTTP-01 验证可能无法访问到 Agent"
		return result
	}
	result.Message = "域名解析已生效；请继续确认解析目标能访问到 HTTP-01 challenge Agent"
	return result
}

func (h *DNSHandler) lookupDomain(ctx context.Context, domain string) ([]string, error) {
	records, err := h.resolver.LookupHost(ctx, domain)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	cname, cnameErr := h.resolver.LookupCNAME(ctx, domain)
	if cnameErr == nil && cname != "" {
		return []string{strings.TrimSuffix(cname, ".")}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no A/AAAA/CNAME records found")
}

func (h *DNSHandler) lookupZone(ctx context.Context, domain string) (string, []string, error) {
	labels := strings.Split(domain, ".")
	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")
		nsRecords, err := h.resolver.LookupNS(ctx, zone)
		if err != nil || len(nsRecords) == 0 {
			continue
		}
		records := make([]string, 0, len(nsRecords))
		for _, record := range nsRecords {
			records = append(records, strings.TrimSuffix(record.Host, "."))
		}
		return zone, records, nil
	}
	return "", nil, fmt.Errorf("no dns zone found for %s", domain)
}
