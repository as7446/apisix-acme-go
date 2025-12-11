package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type ApisixClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewApisixClient(cfg *Config) *ApisixClient {
	return &ApisixClient{
		baseURL: strings.TrimRight(cfg.ApisixAdminURL, "/"),
		token:   cfg.ApisixAdminToken,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type ApisixSSLObject struct {
	ID   string   `json:"id,omitempty"`
	SNIs []string `json:"snis"` // v3 使用 snis 而不是 sni
	Cert string   `json:"cert"`
	Key  string   `json:"key"`
}

func normalizeAPISIXID(domain string) string {
	return strings.ReplaceAll(domain, "*.", "wildcard.")
}

// GetCertificate 获取证书信息
func (c *ApisixClient) GetCertificate(id string) (*ApisixSSLObject, error) {
	normalizedID := normalizeAPISIXID(id)
	url := c.resourceURL("ssl", normalizedID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败：%w", err)
	}
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode >= 300 {
		var respBody bytes.Buffer
		respBody.ReadFrom(resp.Body)
		return nil, fmt.Errorf("APISIX 查询证书失败，状态码=%d, 响应=%s", resp.StatusCode, respBody.String())
	}

	var result struct {
		Value ApisixSSLObject `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败：%w", err)
	}

	return &result.Value, nil
}

// ListSSLs 获取所有证书列表
func (c *ApisixClient) ListSSLs() (map[string]*ApisixSSLObject, error) {
	url := c.resourceURL("ssl", "")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败：%w", err)
	}
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var respBody bytes.Buffer
		respBody.ReadFrom(resp.Body)
		return nil, fmt.Errorf("APISIX 查询证书列表失败，状态码=%d, 响应=%s", resp.StatusCode, respBody.String())
	}

	var result struct {
		List []struct {
			Value ApisixSSLObject `json:"value"`
		} `json:"list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败：%w", err)
	}

	sslMap := make(map[string]*ApisixSSLObject)
	for _, item := range result.List {
		ssl := item.Value
		if len(ssl.SNIs) > 0 {
			domain := ssl.SNIs[0]
			if strings.HasPrefix(domain, "wildcard.") {
				domain = strings.Replace(domain, "wildcard.", "*.", 1)
			}
			sslMap[domain] = &ssl
		} else if ssl.ID != "" {
			domain := ssl.ID
			if strings.HasPrefix(domain, "wildcard.") {
				domain = strings.Replace(domain, "wildcard.", "*.", 1)
			}
			sslMap[domain] = &ssl
		}
	}

	return sslMap, nil
}

// DeleteCertificate 删除证书
func (c *ApisixClient) DeleteCertificate(id string) error {
	normalizedID := normalizeAPISIXID(id)
	url := c.resourceURL("ssl", normalizedID)
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
		var respBody bytes.Buffer
		respBody.ReadFrom(resp.Body)
		return fmt.Errorf("APISIX 删除证书失败，状态码=%d, 响应=%s", resp.StatusCode, respBody.String())
	}
	Log.Printf("APISIX 证书已删除：ID=%s (原始域名=%s)", normalizedID, id)
	return nil
}

// UpsertCertificate 创建或更新证书
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
	Log.Printf("APISIX 证书上传成功：ID=%s (原始域名=%s), SNIs=%v", normalizedID, id, snis)
	return nil
}

// ApisixRoute 路由对象
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

// ApisixUpstream 上游对象
type ApisixUpstream struct {
	Type   string         `json:"type"`
	Scheme string         `json:"scheme,omitempty"`
	Nodes  map[string]int `json:"nodes"`
}

// EnsureChallengeRoute 创建或更新验证路由
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
	Log.Printf("验证路由已创建：ID=%s", cfg.ChallengeRoute.RouteID)
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
	Log.Printf("验证路由已删除：ID=%s", cfg.ChallengeRoute.RouteID)
	return nil
}

// extractPort 提取端口号
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

// resourceURL 构建资源 URL
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
