package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AgentClient Agent 客户端
type AgentClient struct {
	controllerURL string
	httpClient    *http.Client
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	AgentID      string   `json:"agent_id"`
	Zone         string   `json:"zone"`
	Hostname     string   `json:"hostname"`
	IP           string   `json:"ip"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// RegisterResponse 注册响应
type RegisterResponse struct {
	HeartbeatInterval int `json:"heartbeat_interval"`
}

// HeartbeatRequest 心跳请求
type HeartbeatRequest struct {
	AgentID string `json:"agent_id"`
}

// HeartbeatResponse 心跳响应
type HeartbeatResponse struct {
	Status string `json:"status"`
}

// NewAgentClient 创建客户端
func NewAgentClient(controllerURL string) *AgentClient {
	return &AgentClient{
		controllerURL: controllerURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Register 注册 Agent
func (c *AgentClient) Register(req *RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	resp, err := c.httpClient.Post(c.controllerURL+"/v1/agents/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	var registerResp RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	return &registerResp, nil
}

// Heartbeat 发送心跳
func (c *AgentClient) Heartbeat(agentID string) error {
	req := HeartbeatRequest{AgentID: agentID}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request failed: %w", err)
	}

	resp, err := c.httpClient.Post(c.controllerURL+"/v1/agents/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
