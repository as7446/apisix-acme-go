package router

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// skipLoggerMiddleware 可配置跳过路径的访问日志中间件
// skipPaths 匹配规则：
//   - 以 "*" 结尾 → 前缀匹配（如 "/v1/agents/*" 匹配所有 /v1/agents/ 开头的路径）
//   - 否则 → 精确匹配
func skipLoggerMiddleware(skipPaths []string) gin.HandlerFunc {
	exactPaths := make(map[string]struct{})
	var prefixes []string

	for _, p := range skipPaths {
		if strings.HasSuffix(p, "*") {
			prefixes = append(prefixes, strings.TrimSuffix(p, "*"))
		} else {
			exactPaths[p] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// 精确匹配
		if _, ok := exactPaths[path]; ok {
			c.Next()
			return
		}

		// 前缀匹配
		for _, prefix := range prefixes {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}

		// 记录访问日志
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		logger.Log.Info("HTTP",
			"status", c.Writer.Status(),
			"method", c.Request.Method,
			"path", path,
			"latency", latency.String(),
			"client_ip", c.ClientIP(),
		)
	}
}
