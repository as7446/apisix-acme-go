package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler/request"
	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
	"github.com/as7446/apisix-acme-go/internal/application"
)

// TaskHandler Task API 处理
type TaskHandler struct {
	svc *application.TaskService
}

// NewTaskHandler 创建 TaskHandler
func NewTaskHandler(svc *application.TaskService) *TaskHandler {
	return &TaskHandler{svc: svc}
}

// TaskStatusResponse 任务状态响应
type TaskStatusResponse struct {
	Status string `json:"status"`
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
}

// Create 创建任务
// POST /apisix_acme/task_create
func (h *TaskHandler) Create(c *gin.Context) {
	var req request.CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err)
		return
	}

	result, err := h.svc.CreateTask(c.Request.Context(), req.Domain, req.Email, req.Force)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	var message string
	switch result.Status {
	case "skip":
		message = "证书已存在且未过期，跳过操作"
	case "running":
		message = "证书申请中，请稍候"
	default:
		message = "任务已提交，请稍候"
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: message,
		Data: TaskStatusResponse{
			Status: result.Status,
			Domain: result.Domain,
		},
	})
}

// Status 获取任务状态
// GET /apisix_acme/task_status
func (h *TaskHandler) Status(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		response.BadRequest(c, nil)
		return
	}

	result, err := h.svc.GetTask(c.Request.Context(), domain)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	if result == nil {
		c.JSON(200, response.Response{
			Code:    200,
			Message: "任务不存在",
			Data: TaskStatusResponse{
				Status: "error",
				Domain: domain,
				Error:  "域名不存在",
			},
		})
		return
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: TaskStatusResponse{
			Status: result.Status,
			Domain: result.Domain,
			Error:  result.Error,
		},
	})
}
