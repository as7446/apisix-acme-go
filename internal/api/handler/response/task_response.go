package response

type TaskResponse struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agent_id"`
	Type         string                 `json:"type"`
	Domain       string                 `json:"domain"`
	Status       string                 `json:"status"`
	Result       map[string]interface{} `json:"result,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	CreatedAt    int64                  `json:"created_at"`
	DispatchedAt int64                  `json:"dispatched_at,omitempty"`
	CompletedAt  int64                  `json:"completed_at,omitempty"`
	TimeoutAt    int64                  `json:"timeout_at,omitempty"`
	RetryCount   int                    `json:"retry_count"`
}

type TaskListResponse struct {
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Items    []TaskResponse `json:"items"`
}
