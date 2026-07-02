package router

import (
	"expvar"

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

	// 可配置的访问日志中间件（跳过高频接口，默认跳过 heartbeat、task_report、agent 长轮询、healthz）
	r.Use(skipLoggerMiddleware(deps.Config.AccessLogSkipPrefixes))

	// 健康检查
	r.GET("/healthz", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ok"})
	})
	r.GET("/metrics", gin.WrapH(expvar.Handler()))

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

	// ========== RESTful API v1 ==========
	v1 := r.Group("/v1")
	v1.Use(auth)
	{
		// 证书管理
		certs := v1.Group("/certificates")
		{
			certs.POST("", deps.H.Certificate.Create)
			certs.GET("", deps.H.Certificate.List)
			certs.GET("/:domain", deps.H.Certificate.Get)
			certs.GET("/:domain/versions", deps.H.Certificate.Versions)
			certs.PATCH("/:domain/routing", deps.H.Certificate.UpdateRouting)
			certs.DELETE("/:domain", deps.H.Certificate.Delete)
			certs.POST("/:domain/retry", deps.H.Certificate.Retry)
			certs.POST("/:domain/renew", deps.H.Certificate.Renew)
			certs.POST("/:domain/sync", deps.H.Certificate.Sync)
		}

		if deps.H.Task != nil {
			v1.GET("/tasks", deps.H.Task.List)
		}

		// Agent 管理
		if deps.H.Agent != nil {
			agents := v1.Group("/agents")
			{
				agents.POST("/register", deps.H.Agent.Register)
				agents.POST("/heartbeat", deps.H.Agent.Heartbeat)
				agents.GET("", deps.H.Agent.ListAgents)
				agents.GET("/online", deps.H.Agent.ListOnlineAgents)
			}

			// Agent 任务 API（长轮询 + 回报）
			if deps.H.AgentTask != nil {
				agents.GET("/:agent_id/tasks", deps.H.AgentTask.PollTask)
				agents.POST("/task_report", deps.H.AgentTask.ReportTask)
			}
		}
	}

	// 工具页面
	r.GET("/tool.html", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, `<!doctype html>
<html>
<head><title>apisix-acme-go</title></head>
<body>
  <h1>apisix-acme-go</h1>
  <h2>RESTful API v1</h2>
  <ul>
    <li><code>POST /v1/certificates</code> - 创建证书</li>
    <li><code>GET /v1/certificates</code> - 证书列表</li>
    <li><code>GET /v1/certificates?page=1&page_size=10&q=example&sync_status=drifted</code> - 分页/搜索/筛选证书</li>
    <li><code>GET /v1/certificates/:domain</code> - 获取证书状态</li>
    <li><code>GET /v1/certificates/:domain/versions</code> - 获取证书版本</li>
    <li><code>PATCH /v1/certificates/:domain/routing</code> - 更新 challenge_zone 和 sync_zones</li>
    <li><code>DELETE /v1/certificates/:domain</code> - 删除证书</li>
    <li><code>POST /v1/certificates/:domain/retry</code> - 手动重试</li>
    <li><code>POST /v1/certificates/:domain/renew</code> - 手动续期</li>
    <li><code>POST /v1/certificates/:domain/sync</code> - 手动同步</li>
    <li><code>GET /v1/tasks?domain=example.com</code> - 查询 Agent 任务</li>
  </ul>
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
