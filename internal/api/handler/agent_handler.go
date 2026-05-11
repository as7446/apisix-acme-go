package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/application"
	"github.com/as7446/apisix-acme-go/internal/domain/agent"
)

// AgentHandler Agent API 处理
type AgentHandler struct {
	svc *application.AgentService
}

// NewAgentHandler 创建 AgentHandler
func NewAgentHandler(svc *application.AgentService) *AgentHandler {
	return &AgentHandler{svc: svc}
}

// Register Agent 注册
// POST /v1/agents/register
func (h *AgentHandler) Register(c *gin.Context) {
	var req agent.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	resp, err := h.svc.Register(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "register failed"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Heartbeat Agent 心跳
// POST /v1/agents/heartbeat
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	var req agent.HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	resp, err := h.svc.Heartbeat(req.AgentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "heartbeat failed"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListAgents 获取所有 Agent
// GET /v1/agents
func (h *AgentHandler) ListAgents(c *gin.Context) {
	agents, err := h.svc.ListAll()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list agents failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

// ListOnlineAgents 获取所有在线 Agent
// GET /v1/agents/online
func (h *AgentHandler) ListOnlineAgents(c *gin.Context) {
	agents, err := h.svc.ListOnline()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list online agents failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"agents": agents})
}
