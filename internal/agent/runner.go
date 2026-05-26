package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// TaskResponse 从 Controller 拉取的任务
type TaskResponse struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Domain  string                 `json:"domain"`
	Payload map[string]interface{} `json:"payload"`
}

// TaskReport 任务回报
type TaskReport struct {
	AgentID      string                 `json:"agent_id"`
	TaskID       string                 `json:"task_id"`
	Status       string                 `json:"status"`
	Result       map[string]interface{} `json:"result"`
	ErrorMessage string                 `json:"error_message"`
}

// Runner Agent 运行时
type Runner struct {
	cfg            *config.Config
	agentID        string
	hostname       string
	controllerURL  string
	bearerToken    string
	gatewayClient  *GatewayClient
	httpClient     *http.Client
	managedByLabel string
}

// NewRunner 创建 Agent Runner
func NewRunner(cfg *config.Config) *Runner {
	hostname, _ := os.Hostname()
	agentID := cfg.AgentID
	if agentID == "" {
		agentID = hostname
	}

	r := &Runner{
		cfg:            cfg,
		agentID:        agentID,
		hostname:       hostname,
		controllerURL:  cfg.ControllerURL,
		bearerToken:    cfg.BearerToken,
		managedByLabel: cfg.ManagedByLabel,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	if cfg.ApisixAdminURL != "" {
		r.gatewayClient = NewGatewayClient(cfg.ApisixAdminURL, cfg.ApisixAdminToken)
	}

	return r
}

// Run 启动 Agent
func (r *Runner) Run() error {
	logger.Log.Info("Agent 启动",
		"agent_id", r.agentID,
		"zone", r.cfg.AgentRegion,
		"controller", r.controllerURL)

	// 注册
	interval, err := r.register()
	if err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}
	logger.Log.Info("Agent 注册成功", "heartbeat_interval", interval)

	stopCh := make(chan struct{})

	// 心跳循环
	go r.heartbeatLoop(interval, stopCh)

	// 任务拉取循环
	if r.gatewayClient != nil {
		go r.taskPullerLoop(stopCh)
		logger.Log.Info("任务拉取已启动")
	}

	// 等待关闭信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Log.Info("Agent 关闭中...")
	close(stopCh)
	time.Sleep(time.Second)
	logger.Log.Info("Agent 已停止")
	return nil
}

// doPost 发送 POST 请求到 Controller（自动携带 Bearer Token）
func (r *Runner) doPost(url string, body []byte) (*http.Response, error) {
	return r.doPostWithClient(r.httpClient, url, body)
}

// doPostWithClient 用指定 client 发送 POST 请求
func (r *Runner) doPostWithClient(client *http.Client, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearerToken)
	}
	return client.Do(req)
}

// doGet 发送 GET 请求到 Controller（自动携带 Bearer Token）
func (r *Runner) doGet(url string) (*http.Response, error) {
	return r.doGetWithClient(r.httpClient, url)
}

// doGetWithClient 用指定 client 发送 GET 请求
func (r *Runner) doGetWithClient(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearerToken)
	}
	return client.Do(req)
}

func (r *Runner) register() (int, error) {
	reqBody := map[string]interface{}{
		"agent_id":     r.agentID,
		"zone":         r.cfg.AgentRegion,
		"hostname":     r.hostname,
		"ip":           "",
		"version":      "1.0.0",
		"capabilities": []string{"apisix", "http_challenge"},
	}
	body, _ := json.Marshal(reqBody)

	resp, err := r.doPost(r.controllerURL+"/v1/agents/register", body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result struct {
		HeartbeatInterval int `json:"heartbeat_interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result.HeartbeatInterval, nil
}

func (r *Runner) heartbeatLoop(interval int, stopCh <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			sslState := r.collectSSLState()
			if err := r.sendHeartbeat(sslState); err != nil {
				logger.Log.Error("心跳失败", "error", err)
			}
		}
	}
}

func (r *Runner) sendHeartbeat(sslState map[string]string) error {
	reqBody := map[string]interface{}{
		"agent_id":  r.agentID,
		"ssl_state": sslState,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := r.doPost(r.controllerURL+"/v1/agents/heartbeat", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (r *Runner) collectSSLState() map[string]string {
	if r.gatewayClient == nil {
		return nil
	}
	state, err := r.gatewayClient.ListManagedSSLs(r.managedByLabel)
	if err != nil {
		logger.Log.Error("收集 SSL 状态失败", "error", err)
		return nil
	}
	return state
}

func (r *Runner) taskPullerLoop(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		task, err := r.pollTask()
		if err != nil {
			if isTimeoutOrEOF(err) {
				// 长轮询超时或连接被断开，属正常现象，直接重试
				logger.Log.Debug("长轮询超时，继续", "error", err)
				continue
			}
			logger.Log.Error("拉取任务失败", "error", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if task == nil {
			continue
		}

		logger.Log.Info("收到任务", "task_id", task.ID, "type", task.Type, "domain", task.Domain)
		report := r.executeTask(task)

		if err := r.reportTask(report); err != nil {
			logger.Log.Error("回报任务失败", "task_id", task.ID, "error", err)
		}
	}
}

// isTimeoutOrEOF 判断错误是否为超时或 EOF（长轮询正常场景）
func isTimeoutOrEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF") {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(err.Error(), "context deadline exceeded") {
		return true
	}
	return false
}

func (r *Runner) pollTask() (*TaskResponse, error) {
	url := fmt.Sprintf("%s/v1/agents/%s/tasks?timeout=%d", r.controllerURL, r.agentID, r.cfg.LongPollTimeout)
	pollClient := &http.Client{
		Timeout: time.Duration(r.cfg.LongPollTimeout+5) * time.Second,
	}

	resp, err := r.doGetWithClient(pollClient, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var wrapper struct {
		Task TaskResponse `json:"task"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Task, nil
}

func (r *Runner) reportTask(report *TaskReport) error {
	body, _ := json.Marshal(report)
	resp, err := r.doPost(r.controllerURL+"/v1/agents/task_report", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (r *Runner) executeTask(task *TaskResponse) *TaskReport {
	report := &TaskReport{
		AgentID: r.agentID,
		TaskID:  task.ID,
	}

	switch task.Type {
	case "inject_challenge":
		r.execInjectChallenge(task, report)
	case "remove_challenge":
		r.execRemoveChallenge(task, report)
	case "sync_cert":
		r.execSyncCert(task, report)
	case "delete_cert":
		r.execDeleteCert(task, report)
	default:
		report.Status = "failed"
		report.ErrorMessage = fmt.Sprintf("未知任务类型: %s", task.Type)
	}
	return report
}

func (r *Runner) execInjectChallenge(task *TaskResponse, report *TaskReport) {
	routeName, _ := task.Payload["route_name"].(string)
	domain := task.Domain
	var upstreamNodes []string
	if nodes, ok := task.Payload["upstream_nodes"].([]interface{}); ok {
		for _, n := range nodes {
			if s, ok := n.(string); ok {
				upstreamNodes = append(upstreamNodes, s)
			}
		}
	}
	upstreamScheme, _ := task.Payload["upstream_scheme"].(string)
	if upstreamScheme == "" {
		upstreamScheme = "http"
	}

	routeID, err := r.gatewayClient.EnsureChallengeRoute(routeName, domain, upstreamNodes, upstreamScheme)
	if err != nil {
		report.Status = "failed"
		report.ErrorMessage = err.Error()
		return
	}
	report.Status = "success"
	report.Result = map[string]interface{}{"route_id": routeID}
}

func (r *Runner) execRemoveChallenge(task *TaskResponse, report *TaskReport) {
	routeID, _ := task.Payload["route_id"].(string)
	if routeID == "" {
		report.Status = "failed"
		report.ErrorMessage = "route_id 为空"
		return
	}
	if err := r.gatewayClient.DeleteRoute(routeID); err != nil {
		report.Status = "failed"
		report.ErrorMessage = err.Error()
		return
	}
	report.Status = "success"
}

func (r *Runner) execSyncCert(task *TaskResponse, report *TaskReport) {
	apisixID, _ := task.Payload["apisix_id"].(string)
	certPEM, _ := task.Payload["cert_pem"].(string)
	keyPEM, _ := task.Payload["key_pem"].(string)
	expiresAt, _ := task.Payload["expires_at"].(float64)

	var snis []string
	if s, ok := task.Payload["snis"].([]interface{}); ok {
		for _, v := range s {
			if str, ok := v.(string); ok {
				snis = append(snis, str)
			}
		}
	}
	var labels map[string]string
	if l, ok := task.Payload["labels"].(map[string]interface{}); ok {
		labels = make(map[string]string)
		for k, v := range l {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}

	if apisixID == "" || certPEM == "" || keyPEM == "" {
		report.Status = "failed"
		report.ErrorMessage = "sync_cert 参数不完整"
		return
	}

	if err := r.gatewayClient.UpsertCertificate(apisixID, snis, certPEM, keyPEM, int64(expiresAt), labels); err != nil {
		report.Status = "failed"
		report.ErrorMessage = err.Error()
		return
	}
	report.Status = "success"
}

func (r *Runner) execDeleteCert(task *TaskResponse, report *TaskReport) {
	apisixID, _ := task.Payload["apisix_id"].(string)
	if apisixID == "" {
		report.Status = "failed"
		report.ErrorMessage = "apisix_id 为空"
		return
	}
	if err := r.gatewayClient.DeleteCertificate(apisixID); err != nil {
		report.Status = "failed"
		report.ErrorMessage = err.Error()
		return
	}
	report.Status = "success"
}
