package router

import (
	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler"
	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// Dependencies 路由依赖
type Dependencies struct {
	Config    *config.Config
	H         *handler.Container
	HTTPStore *acme.HTTPChallengeStore
}

// New 创建 Gin 路由
func New(deps *Dependencies) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// 健康检查
	r.GET("/healthz", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ok"})
	})

	// HTTP-01 验证端点
	r.GET("/.well-known/acme-challenge/:token", func(c *gin.Context) {
		token := c.Param("token")
		if token == "" {
			c.String(400, "token required")
			return
		}
		if keyAuth, ok := deps.HTTPStore.Get(token); ok {
			logger.Log.Info("HTTP-01 验证请求命中", "host", c.Request.Host, "url", "http://"+c.Request.Host+c.Request.RequestURI, "token", token)
			c.String(200, keyAuth)
			return
		}
		logger.Log.Info("HTTP-01 验证请求未命中", "host", c.Request.Host, "url", "http://"+c.Request.Host+c.Request.RequestURI, "token", token)
		c.String(404, "token not found")
	})

	// 认证中间件
	auth := authMiddleware(deps.Config.BearerToken)

	// ACME API 路由
	apiGroup := r.Group("/apisix_acme")
	apiGroup.Use(auth)
	{
		apiGroup.POST("/task_create", deps.H.Task.Create)
		apiGroup.GET("/task_status", deps.H.Task.Status)
		apiGroup.GET("/cert_info", deps.H.Cert.Info)
		apiGroup.DELETE("/cert_delete", deps.H.Cert.Delete)
	}

	// Agent API 路由
	if deps.H.Agent != nil {
		v1 := r.Group("/v1")
		{
			agents := v1.Group("/agents")
			{
				agents.POST("/register", deps.H.Agent.Register)
				agents.POST("/heartbeat", deps.H.Agent.Heartbeat)
				agents.GET("", deps.H.Agent.ListAgents)
				agents.GET("/online", deps.H.Agent.ListOnlineAgents)
			}
		}
	}

	// 工具页面
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

func authMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" {
			c.Next()
			return
		}
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(401, response.Response{Code: 401, Message: "未授权"})
			return
		}
		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			c.AbortWithStatusJSON(401, response.Response{Code: 401, Message: "未授权"})
			return
		}
		if auth[len(prefix):] != token {
			c.AbortWithStatusJSON(401, response.Response{Code: 401, Message: "未授权"})
			return
		}
		c.Next()
	}
}
