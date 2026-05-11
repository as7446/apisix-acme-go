package request

// CreateTaskRequest 创建任务请求
type CreateTaskRequest struct {
	Domain string `json:"domain" binding:"required"`
	Email  string `json:"email"`
	Force  bool   `json:"force"`
}
