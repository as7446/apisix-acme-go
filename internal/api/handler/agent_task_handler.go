package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/controller/dispatch"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
)

// AgentTaskHandler Agent 任务 API 处理
type AgentTaskHandler struct {
	dispatcher *dispatch.TaskDispatcher
	cfg        *config.Config
}

// NewAgentTaskHandler 创建 AgentTaskHandler
func NewAgentTaskHandler(dispatcher *dispatch.TaskDispatcher, cfg *config.Config) *AgentTaskHandler {
	return &AgentTaskHandler{
		dispatcher: dispatcher,
		cfg:        cfg,
	}
}

// PollTask Agent 长轮询拉取任务
// GET /v1/agents/:agent_id/tasks?timeout=30
func (h *AgentTaskHandler) PollTask(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	// 解析超时参数
	timeoutSec := h.cfg.LongPollTimeout
	if t := c.Query("timeout"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 && parsed <= 60 {
			timeoutSec = parsed
		}
	}

	timeout := time.Duration(timeoutSec) * time.Second
	task, err := h.dispatcher.WaitForTask(agentID, timeout)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if task == nil {
		// 超时无任务
		c.Status(http.StatusNoContent)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"task": task.ToResponse(),
	})
}

// ReportTask Agent 任务回报
// POST /v1/agents/task_report
func (h *AgentTaskHandler) ReportTask(c *gin.Context) {
	var req agenttask.TaskReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if err := h.dispatcher.HandleReport(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "accepted"})
}
