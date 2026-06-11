package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GatewayClient Agent 侧的 APISIX 网关客户端
type GatewayClient struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewGatewayClient 创建 APISIX 网关客户端
func NewGatewayClient(adminURL, adminToken string) *GatewayClient {
	return &GatewayClient{
		baseURL: strings.TrimRight(adminURL, "/"),
		token:   adminToken,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SSLObject APISIX SSL 对象
type SSLObject struct {
	ID     string            `json:"id,omitempty"`
	SNIs   []string          `json:"snis"`
	Cert   string            `json:"cert"`
	Key    string            `json:"key"`
	Labels map[string]string `json:"labels,omitempty"`
}

// UpsertCertificate 创建或更新 SSL 证书
func (c *GatewayClient) UpsertCertificate(id string, snis []string, certPEM, keyPEM string, expiresAt int64, labels map[string]string) error {
	body := map[string]interface{}{
		"snis":   snis,
		"cert":   certPEM,
		"key":    keyPEM,
		"labels": labels,
	}
	data, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/apisix/admin/ssls/%s", c.baseURL, id)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("X-API-KEY", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APISIX 返回错误: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}

// DeleteCertificate 删除 SSL 证书
func (c *GatewayClient) DeleteCertificate(id string) error {
	url := fmt.Sprintf("%s/apisix/admin/ssls/%s", c.baseURL, id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APISIX 返回错误: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}

// EnsureChallengeRoute 创建 HTTP-01 验证路由
func (c *GatewayClient) EnsureChallengeRoute(routeName, domain string, upstreamNodes []string, upstreamScheme string) (string, error) {
	if len(upstreamNodes) == 0 {
		return "", fmt.Errorf("upstream_nodes 为空，无法创建 challenge route（需配置 Controller 的可达地址）")
	}

	nodes := make(map[string]int)
	for _, n := range upstreamNodes {
		nodes[n] = 1
	}

	routeID := fmt.Sprintf("%s_%s", routeName, certSafeID(domain))
	body := map[string]interface{}{
		"uri":    "/.well-known/acme-challenge/*",
		"host":   domain,
		"name":   routeID,
		"status": 1,
		"upstream": map[string]interface{}{
			"type":   "roundrobin",
			"nodes":  nodes,
			"scheme": upstreamScheme,
		},
	}
	data, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/apisix/admin/routes/%s", c.baseURL, routeID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-KEY", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 APISIX 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("APISIX 返回错误: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return routeID, nil
}

func certSafeID(domain string) string {
	id := strings.ReplaceAll(domain, "*.", "wildcard.")
	id = strings.ReplaceAll(id, ".", "_")
	return strings.ReplaceAll(id, "*", "wildcard")
}

// DeleteRoute 删除路由
func (c *GatewayClient) DeleteRoute(routeID string) error {
	url := fmt.Sprintf("%s/apisix/admin/routes/%s", c.baseURL, routeID)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 APISIX 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APISIX 返回错误: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ListManagedSSLs 获取所有由本服务管理的 SSL 证书并返回 domain → fingerprint map
func (c *GatewayClient) ListManagedSSLs(managedByLabel string) (map[string]string, error) {
	url := fmt.Sprintf("%s/apisix/admin/ssls", c.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 APISIX 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("APISIX 返回错误: status=%d", resp.StatusCode)
	}

	var result struct {
		List []struct {
			Value SSLObject `json:"value"`
		} `json:"list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	sslState := make(map[string]string)
	for _, item := range result.List {
		ssl := item.Value
		if managedByLabel != "" {
			if ssl.Labels == nil || ssl.Labels["managed-by"] != managedByLabel {
				continue
			}
		}
		fingerprint := CalculateFingerprint(ssl.Cert)
		for _, sni := range ssl.SNIs {
			sslState[sni] = fingerprint
		}
	}
	return sslState, nil
}

// CalculateFingerprint 计算证书指纹
func CalculateFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}
