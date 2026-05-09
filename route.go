package main

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/domain/task"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/store/cache"
)

type CreateTaskRequest struct {
	Domain string `json:"domain" binding:"required"`
	Email  string `json:"email"`
	Force  bool   `json:"force"`
}

type TaskStatusResponse struct {
	Status string `json:"status"`
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func authMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" {
			c.Next()
			return
		}
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) || strings.TrimSpace(auth[len(prefix):]) != token {
			c.AbortWithStatusJSON(401, APIResponse{Code: 401, Message: "未授权"})
			return
		}
		c.Next()
	}
}

func newRouter(cfg *config.Config, tm *task.Manager, certRepo cert.CertRepository, apiClient *acme.ApisixClient, cache *cache.FileCache, httpStore *acme.HTTPChallengeStore) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// 健康检查
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// HTTP-01 验证端点
	r.GET("/.well-known/acme-challenge/:token", func(c *gin.Context) {
		token := c.Param("token")
		if token == "" {
			c.String(400, "token required")
			return
		}
		if keyAuth, ok := httpStore.Get(token); ok {
			logger.Log.Info("HTTP-01 验证请求命中", "host", c.Request.Host, "url", "http://"+c.Request.Host+c.Request.RequestURI, "token", token)
			c.String(200, keyAuth)
			return
		}
		logger.Log.Info("HTTP-01 验证请求未命中", "host", c.Request.Host, "url", "http://"+c.Request.Host+c.Request.RequestURI, "token", token)
		c.String(404, "token not found")
	})

	apiGroup := r.Group("/apisix_acme")
	apiGroup.Use(authMiddleware(cfg.BearerToken))

	apiGroup.POST("/task_create", func(c *gin.Context) {
		var req CreateTaskRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, APIResponse{Code: 400, Message: "请求参数格式错误"})
			return
		}

		t := tm.CreateOrUpdateTask(req.Domain, req.Email, req.Force)

		var message string
		switch t.Status {
		case task.TaskStatusSkip:
			message = "证书已存在且未过期，跳过操作"
		case task.TaskStatusRunning:
			message = "证书申请中，请稍候"
		default:
			message = "任务已提交，请稍候"
		}

		c.JSON(200, APIResponse{
			Code:    200,
			Message: message,
			Data: TaskStatusResponse{
				Status: string(t.Status),
				Domain: t.Domain,
			},
		})
	})

	apiGroup.GET("/task_status", func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		t := tm.GetTask(domain)
		if t == nil {
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
			Status: string(t.Status),
			Domain: t.Domain,
		}
		if t.Status == task.TaskStatusError && t.Error != "" {
			resp.Error = t.Error
		}
		c.JSON(200, APIResponse{
			Code: 200,
			Data: resp,
		})
	})

	apiGroup.GET("/cert_info", func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		certRec, ok := certRepo.GetWithDeleted(domain)
		if !ok {
			c.JSON(404, APIResponse{Code: 404, Message: "未找到证书"})
			return
		}
		resp := map[string]interface{}{
			"domain":        certRec.Domain,
			"snis":          certRec.SNIs,
			"not_before":    certRec.NotBefore,
			"not_after":     certRec.NotAfter,
			"apisix_id":     certRec.APISIXID,
			"fingerprint":   certRec.Fingerprint,
			"serial_number": certRec.SerialNumber,
			"deleted":       certRec.Deleted,
			"created_at":    certRec.CreatedAt,
			"updated_at":    certRec.UpdatedAt,
		}
		c.JSON(200, APIResponse{Code: 200, Data: resp, Message: "获取证书信息成功"})
	})

	apiGroup.DELETE("/cert_delete", func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, APIResponse{Code: 400, Message: "域名参数必填"})
			return
		}
		rec, ok := certRepo.GetWithDeleted(domain)
		if !ok {
			c.JSON(404, APIResponse{Code: 404, Message: "未找到证书"})
			return
		}
		if rec.Deleted {
			c.JSON(200, APIResponse{Code: 200, Message: "已删除"})
			return
		}
		if err := apiClient.DeleteCertificate(domain); err != nil {
			c.JSON(500, APIResponse{Code: 500, Message: fmt.Sprintf("删除 APISIX 证书失败: %v", err)})
			return
		}
		if err := certRepo.MarkDeleted(domain); err != nil {
			c.JSON(500, APIResponse{Code: 500, Message: "标记删除失败"})
			return
		}
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