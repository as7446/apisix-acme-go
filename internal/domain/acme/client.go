package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// ApisixSSLObject APISIX SSL 对象
type ApisixSSLObject struct {
	ID         string            `json:"id,omitempty"`
	SNIs       []string          `json:"snis"`
	Cert       string            `json:"cert"`
	Key        string            `json:"key"`
	Labels     map[string]string `json:"labels,omitempty"`
	UpdateTime int64             `json:"update_time,omitempty"`
}

// ApisixClient APISIX 客户端
type ApisixClient struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewApisixClient 创建 APISIX 客户端
func NewApisixClient(cfg *config.Config) *ApisixClient {
	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &ApisixClient{
		baseURL: strings.TrimRight(cfg.ApisixAdminURL, "/"),
		token:   cfg.ApisixAdminToken,
		client: &http.Client{
			Timeout:   time.Duration(cfg.HTTPTimeout) * time.Second,
			Transport: transport,
		},
	}
}

// GetCertificate 获取证书信息
func (c *ApisixClient) GetCertificate(id string) (*cert.ApisixSSLObject, error) {
	normalizedID := cert.NormalizeAPISIXID(id)
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
		Value cert.ApisixSSLObject `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败：%w", err)
	}

	return &result.Value, nil
}

// ListSSLs 获取所有证书列表
func (c *ApisixClient) ListSSLs() (map[string]*cert.ApisixSSLObject, error) {
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
			Value cert.ApisixSSLObject `json:"value"`
		} `json:"list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败：%w", err)
	}

	sslMap := make(map[string]*cert.ApisixSSLObject)
	for _, item := range result.List {
		ssl := &item.Value
		key := ssl.ID
		if key == "" && len(ssl.SNIs) > 0 {
			key = ssl.SNIs[0]
		}
		if key != "" {
			if strings.HasPrefix(key, "wildcard.") {
				key = strings.Replace(key, "wildcard.", "*.", 1)
			}
			sslMap[key] = ssl
		}
	}

	return sslMap, nil
}

// DeleteCertificate 删除证书
func (c *ApisixClient) DeleteCertificate(id string) error {
	normalizedID := cert.NormalizeAPISIXID(id)
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
	logger.Log.Info("APISIX 证书已删除", "id", normalizedID, "original_domain", id)
	return nil
}

// IsManagedByUs 判断该 SSL 资源是否由本服务管理
func (c *ApisixClient) IsManagedByUs(ssl *cert.ApisixSSLObject, label string) bool {
	if ssl == nil || ssl.Labels == nil {
		return false
	}
	v, ok := ssl.Labels["managed-by"]
	return ok && v == label
}

// GetRevisionFromSSL 从 APISIX SSL 的 labels 中解析本地 revision
func (c *ApisixClient) GetRevisionFromSSL(ssl *cert.ApisixSSLObject) int {
	if ssl == nil || ssl.Labels == nil {
		return 0
	}
	s, ok := ssl.Labels["x-acme-revision"]
	if !ok {
		return 0
	}
	var rev int
	_, _ = fmt.Sscanf(s, "%d", &rev)
	return rev
}

// UpsertCertificate 创建或更新证书
func (c *ApisixClient) UpsertCertificate(id string, snis []string, certPEM, keyPEM string, expiresAt int64, labels map[string]string) error {
	normalizedID := cert.NormalizeAPISIXID(id)
	obj := ApisixSSLObject{
		ID:     normalizedID,
		SNIs:   snis,
		Cert:   certPEM,
		Key:    keyPEM,
		Labels: labels,
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
	logger.Log.Info("APISIX 证书上传成功", "id", normalizedID, "original_domain", id, "snis", snis)
	return nil
}

// ApisixRoute 路由对象
type ApisixRoute struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	URI      string         `json:"uri,omitempty"`
	Methods  []string       `json:"methods,omitempty"`
	Hosts    []string       `json:"hosts,omitempty"`
	Priority int            `json:"priority,omitempty"`
	Status   int            `json:"status,omitempty"`
	Upstream ApisixUpstream `json:"upstream"`
}

// ApisixUpstream 上游对象
type ApisixUpstream struct {
	Type   string         `json:"type"`
	Scheme string         `json:"scheme,omitempty"`
	Nodes  map[string]int `json:"nodes"`
}

// EnsureChallengeRoute 创建或更新验证路由
func (c *ApisixClient) EnsureChallengeRoute(cfg *config.Config, domain string) (string, error) {
	if !cfg.ChallengeRoute.Enable {
		return "", nil
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
		return "", fmt.Errorf("验证路由节点为空")
	}

	routeID := uuid.New().String()
	route := ApisixRoute{
		ID:       routeID,
		Name:     cfg.ChallengeRoute.RouteName,
		URI:      "/.well-known/acme-challenge/*",
		Methods:  []string{"GET"},
		Hosts:    []string{domain},
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
		return "", fmt.Errorf("序列化路由对象失败：%w", err)
	}
	url := c.resourceURL("routes", routeID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-API-KEY", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 APISIX 失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("APISIX 创建验证路由失败，状态码=%d", resp.StatusCode)
	}
	logger.Log.Info("验证路由已创建", "id", routeID)
	return routeID, nil
}

// DeleteChallengeRoute 删除验证路由
func (c *ApisixClient) DeleteChallengeRoute(routeID string) error {
	if routeID == "" {
		return nil
	}
	url := c.resourceURL("routes", routeID)
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
	logger.Log.Info("验证路由已删除", "id", routeID)
	return nil
}

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

func (c *ApisixClient) resourceURL(resource, id string) string {
	pathResource := resource
	if resource == "ssl" {
		pathResource = "ssls"
	}
	builder := strings.Builder{}
	builder.WriteString(c.baseURL)
	builder.WriteString("/apisix/admin/")
	builder.WriteString(pathResource)
	if id != "" {
		builder.WriteString("/")
		builder.WriteString(id)
	}
	return builder.String()
}