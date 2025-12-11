package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type CreateTaskRequest struct {
	Domain string `json:"domain" binding:"required"`
	Email  string `json:"email"`
	Force  bool   `json:"force"`
}

type TaskStatusResponse struct {
	Status string `json:"status"` // 任务状态：created, running, success, error, skip
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func checkBearer(r *http.Request, token string) bool {
	if token == "" {
		return true // 未配置 token 则不校验
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return strings.TrimSpace(auth[len(prefix):]) == token
}

func NewRouter(cfg *Config, tm *TaskManager, store *StormCertStore, api *ApisixClient, cache *CertCache, httpStore *HTTPChallengeStore) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.GET("/.well-known/acme-challenge/:token", func(c *gin.Context) {
		token := c.Param("token")
		if token == "" {
			c.String(400, "token required")
			return
		}
		if keyAuth, ok := httpStore.Get(token); ok {
			Log.Printf("HTTP-01 验证请求：host=%s, url=http://%s%s, token=%s, 命中", c.Request.Host, c.Request.Host, c.Request.RequestURI, token)
			c.String(200, keyAuth)
			return
		}
		Log.Printf("HTTP-01 验证请求：host=%s, url=http://%s%s, token=%s, 未命中", c.Request.Host, c.Request.Host, c.Request.RequestURI, token)
		c.String(404, "token not found")
	})

	apiGroup := r.Group("/apisix_acme")

	apiGroup.POST("/task_create", func(c *gin.Context) {
		if !checkBearer(c.Request, cfg.BearerToken) {
			c.JSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		var req CreateTaskRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, APIResponse{Code: 400, Message: "请求参数格式错误"})
			return
		}

		task := tm.CreateOrUpdateTask(req.Domain, req.Email, req.Force)

		var message string
		switch task.Status {
		case TaskStatusSkip:
			message = "证书已存在且未过期，跳过操作"
		case TaskStatusRunning:
			message = "证书申请中，请稍候"
		default:
			message = "任务已提交，请稍候"
		}

		c.JSON(200, APIResponse{
			Code:    200,
			Message: message,
			Data: TaskStatusResponse{
				Status: string(task.Status),
				Domain: task.Domain,
			},
		})
	})

	apiGroup.GET("/task_status", func(c *gin.Context) {
		if !checkBearer(c.Request, cfg.BearerToken) {
			c.JSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		task := tm.GetTask(domain)
		if task == nil {
			c.JSON(200, APIResponse{
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
		resp := TaskStatusResponse{
			Status: string(task.Status),
			Domain: task.Domain,
		}
		if task.Status == TaskStatusError && task.Error != "" {
			resp.Error = task.Error
		}
		c.JSON(200, APIResponse{
			Code: 200,
			Data: resp,
		})
	})

	apiGroup.GET("/cert_info", func(c *gin.Context) {
		if !checkBearer(c.Request, cfg.BearerToken) {
			c.JSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		cert, ok := store.GetWithDeleted(domain)
		if !ok {
			c.JSON(404, APIResponse{Code: 404, Message: "未找到证书"})
			return
		}
		resp := map[string]interface{}{
			"domain":        cert.Domain,
			"snis":          cert.SNIs,
			"not_before":    cert.NotBefore,
			"not_after":     cert.NotAfter,
			"apisix_id":     cert.APISIXID,
			"fingerprint":   cert.Fingerprint,
			"serial_number": cert.SerialNumber,
			"deleted":       cert.Deleted,
			"created_at":    cert.CreatedAt,
			"updated_at":    cert.UpdatedAt,
		}
		c.JSON(200, APIResponse{Code: 200, Data: resp})
	})

	apiGroup.DELETE("/cert_delete", func(c *gin.Context) {
		if !checkBearer(c.Request, cfg.BearerToken) {
			c.JSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		rec, ok := store.GetWithDeleted(domain)
		if !ok {
			c.JSON(404, APIResponse{Code: 404, Message: "未找到证书"})
			return
		}
		if rec.Deleted {
			c.JSON(200, APIResponse{Code: 200, Message: "已删除"})
			return
		}
		_ = cache.Remove(domain)
		if err := api.DeleteCertificate(domain); err != nil {
			c.JSON(500, APIResponse{Code: 500, Message: fmt.Sprintf("删除 APISIX 证书失败: %v", err)})
			return
		}
		if err := store.MarkDeleted(domain); err != nil {
			c.JSON(500, APIResponse{Code: 500, Message: "标记删除失败"})
			return
		}
		_ = store.SaveTask(domain, string(TaskStatusSuccess), "deleted")
		_ = store.CleanupTasks(cfg.TaskRetentionHrs)
		c.JSON(200, APIResponse{Code: 200, Message: "已删除"})
	})

	r.GET("/apisix_acme/tool.html", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, `<!doctype html>
<html>
<head><title>apisix-acme-go 工具页面</title></head>
<body>
  <h1>apisix-acme-go</h1>
  <p>可通过 curl 调用 <code>/apisix_acme/task_create</code> 与 <code>/apisix_acme/task_status</code> API。</p>
</body>
</html>`)
	})

	return r
}
