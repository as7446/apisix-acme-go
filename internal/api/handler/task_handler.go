package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
)

type TaskHandler struct {
	repo agenttask.AgentTaskRepository
}

func NewTaskHandler(repo agenttask.AgentTaskRepository) *TaskHandler {
	return &TaskHandler{repo: repo}
}

// List 查询 Agent 任务列表
// GET /v1/tasks
func (h *TaskHandler) List(c *gin.Context) {
	result, err := h.repo.List(agenttask.TaskListQuery{
		Page:    intQuery(c, "page", 1),
		Size:    intQuery(c, "page_size", 20),
		Domain:  c.Query("domain"),
		AgentID: c.Query("agent_id"),
		Type:    c.Query("type"),
		Status:  c.Query("status"),
	})
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	items := make([]response.TaskResponse, 0, len(result.Items))
	for _, task := range result.Items {
		items = append(items, response.TaskResponse{
			ID:           task.ID,
			AgentID:      task.AgentID,
			Type:         string(task.Type),
			Domain:       task.Domain,
			Status:       string(task.Status),
			Result:       task.Result,
			ErrorMessage: task.ErrorMessage,
			CreatedAt:    task.CreatedAt,
			DispatchedAt: task.DispatchedAt,
			CompletedAt:  task.CompletedAt,
			TimeoutAt:    task.TimeoutAt,
			RetryCount:   task.RetryCount,
		})
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: response.TaskListResponse{
			Total:    result.Total,
			Page:     result.Page,
			PageSize: result.Size,
			Items:    items,
		},
	})
}
