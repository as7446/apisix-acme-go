package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type ApisixClient struct {
	baseURL string
	token   string
	client  *http.Client
	logger  *log.Logger
}

func NewApisixClient(cfg *Config, logger *log.Logger) *ApisixClient {
	return &ApisixClient{
		baseURL: strings.TrimRight(cfg.ApisixAdminURL, "/"),
		token:   cfg.ApisixAdminToken,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		logger: logger,
	}
}

type ApisixSSLObject struct {
	ID   string   `json:"id,omitempty"`
	SNIs []string `json:"snis"` // v3 使用 snis 而不是 sni
	Cert string   `json:"cert"`
	Key  string   `json:"key"`
}

func normalizeAPISIXID(domain string) string {
	// 将 *.example.com 转换为 wildcard.example.com
	return strings.ReplaceAll(domain, "*.", "wildcard.")
}

// UpsertCertificate 在 APISIX 中创建或更新证书
func (c *ApisixClient) UpsertCertificate(id string, snis []string, certPEM, keyPEM string, expiresAt int64) error {
	normalizedID := normalizeAPISIXID(id)
	obj := ApisixSSLObject{
		ID:   normalizedID,
		SNIs: snis,
		Cert: certPEM,
		Key:  keyPEM,
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("序列化证书对象失败：%w", err)
	}
	url := c.resourceURL("ssl", normalizedID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var respBody bytes.Buffer
		respBody.ReadFrom(resp.Body)
		return fmt.Errorf("APISIX 上传证书失败，状态码=%d, 响应=%s", resp.StatusCode, respBody.String())
	}
	c.logger.Printf("APISIX 证书上传成功：ID=%s (原始域名=%s), SNIs=%v", normalizedID, id, snis)
	return nil
}

// ApisixRoute APISIX 路由对象
type ApisixRoute struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	URI      string         `json:"uri,omitempty"`
	URIs     []string       `json:"uris,omitempty"`
	Methods  []string       `json:"methods,omitempty"`
	Hosts    []string       `json:"hosts,omitempty"`
	Priority int            `json:"priority,omitempty"`
	Status   int            `json:"status,omitempty"`
	Upstream ApisixUpstream `json:"upstream"`
	Plugins  map[string]any `json:"plugins,omitempty"`
	Vars     [][]string     `json:"vars,omitempty"`
}

// ApisixUpstream APISIX 上游对象
type ApisixUpstream struct {
	Type   string         `json:"type"`
	Scheme string         `json:"scheme,omitempty"`
	Nodes  map[string]int `json:"nodes"`
}

// EnsureChallengeRoute 创建或更新 APISIX 路由，将 /.well-known/acme-challenge/* 转发到当前服务
func (c *ApisixClient) EnsureChallengeRoute(cfg *Config) error {
	if !cfg.ChallengeRoute.Enable {
		return nil
	}
	nodes := make(map[string]int)
	if len(cfg.ChallengeRoute.UpstreamNodes) == 0 {
		host := "127.0.0.1"
		port := extractPort(cfg.Listen)
		if port == "" {
			port = "8080"
		}
		nodes[fmt.Sprintf("%s:%s", host, port)] = 1
	} else {
		for _, n := range cfg.ChallengeRoute.UpstreamNodes {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			nodes[n] = 1
		}
	}
	if len(nodes) == 0 {
		return fmt.Errorf("验证路由节点为空")
	}

	route := ApisixRoute{
		ID:       cfg.ChallengeRoute.RouteID,
		Name:     "apisix_acme_http01",
		URI:      "/.well-known/acme-challenge/*",
		Methods:  []string{"GET"},
		Hosts:    cfg.ChallengeRoute.Hosts,
		Priority: cfg.ChallengeRoute.Priority,
		Status:   1,
		Upstream: ApisixUpstream{
			Type:   "roundrobin",
			Scheme: cfg.ChallengeRoute.UpstreamScheme,
			Nodes:  nodes,
		},
	}
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("序列化路由对象失败：%w", err)
	}
	url := c.resourceURL("routes", cfg.ChallengeRoute.RouteID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("APISIX 创建验证路由失败，状态码=%d", resp.StatusCode)
	}
	c.logger.Printf("验证路由已创建：ID=%s", cfg.ChallengeRoute.RouteID)
	return nil
}

// DeleteChallengeRoute 删除验证路由
func (c *ApisixClient) DeleteChallengeRoute(cfg *Config) error {
	if !cfg.ChallengeRoute.Enable {
		return nil
	}
	url := c.resourceURL("routes", cfg.ChallengeRoute.RouteID)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败：%w", err)
	}
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("APISIX 删除验证路由失败，状态码=%d", resp.StatusCode)
	}
	c.logger.Printf("验证路由已删除：ID=%s", cfg.ChallengeRoute.RouteID)
	return nil
}

// extractPort 从地址中提取端口号
func extractPort(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	if strings.Contains(addr, ":") {
		if _, port, err := net.SplitHostPort(addr); err == nil {
			return port
		}
		parts := strings.Split(addr, ":")
		return parts[len(parts)-1]
	}
	return ""
}

// resourceURL 构建 APISIX Admin API 资源 URL
func (c *ApisixClient) resourceURL(resource, id string) string {
	pathResource := resource
	if resource == "ssl" {
		pathResource = "ssls" // v3 API 使用 ssls
	}
	builder := strings.Builder{}
	builder.WriteString(c.baseURL)
	builder.WriteString("/apisix/admin")
	builder.WriteString("/")
	builder.WriteString(pathResource)
	if id != "" {
		builder.WriteString("/")
		builder.WriteString(id)
	}
	return builder.String()
}
