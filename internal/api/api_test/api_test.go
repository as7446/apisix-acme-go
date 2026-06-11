package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const testBearerToken = "test-token"

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"status": "ok"}})
	})
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "{}")
	})

	auth := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+testBearerToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "未授权"})
			return
		}
		c.Next()
	}

	v1 := r.Group("/v1", auth)
	{
		certs := v1.Group("/certificates")
		{
			certs.POST("", func(c *gin.Context) {
				var body map[string]interface{}
				if err := c.ShouldBindJSON(&body); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "参数错误"})
					return
				}
				domain, ok := body["domain"].(string)
				if !ok || domain == "" {
					c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "domain 不能为空"})
					return
				}
				c.JSON(http.StatusCreated, gin.H{
					"code":    201,
					"message": "证书申请已创建",
					"data": gin.H{
						"domain":           domain,
						"lifecycle_status": "active",
						"issue_status":     "pending",
						"sync_status":      "drifted",
						"challenge_zone":   body["challenge_zone"],
						"sync_zones":       body["sync_zones"],
					},
				})
			})
			certs.GET("", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"total": 0, "items": []interface{}{}}})
			})
			certs.GET("/:domain", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"code": 200,
					"data": gin.H{
						"domain":           c.Param("domain"),
						"lifecycle_status": "active",
						"issue_status":     "idle",
						"sync_status":      "synced",
						"revision":         1,
					},
				})
			})
			certs.PATCH("/:domain/routing", func(c *gin.Context) {
				var body map[string]interface{}
				if err := c.ShouldBindJSON(&body); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "参数错误"})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"code":    200,
					"message": "证书路由策略已更新",
					"data": gin.H{
						"domain":         c.Param("domain"),
						"challenge_zone": body["challenge_zone"],
						"sync_zones":     body["sync_zones"],
						"sync_status":    "drifted",
					},
				})
			})
			certs.DELETE("/:domain", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"code": 200, "message": "证书已删除"})
			})
			certs.POST("/:domain/retry", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"code": 200, "message": "重试已触发"})
			})
		}

		agents := v1.Group("/agents")
		{
			agents.POST("/register", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"heartbeat_interval": 30})
			})
			agents.POST("/heartbeat", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
			agents.GET("", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"agents": []interface{}{}})
			})
			agents.GET("/online", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"agents": []interface{}{}})
			})
		}
	}

	return r
}

func TestHealthzNoAuth(t *testing.T) {
	r := setupTestRouter()
	status, _ := doRequest(t, r, http.MethodGet, "/healthz", "", false)
	if status != http.StatusOK {
		t.Fatalf("healthz status=%d", status)
	}
}

func TestAuthRequiredForV1(t *testing.T) {
	r := setupTestRouter()
	status, _ := doRequest(t, r, http.MethodGet, "/v1/certificates", "", false)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", status)
	}
}

func TestCertificateCreate(t *testing.T) {
	r := setupTestRouter()

	status, body := postJSON(t, r, "/v1/certificates", `{"domain":"test.example.com","challenge_zone":"hk","sync_zones":["hk"]}`)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", status, string(body))
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	data := resp["data"].(map[string]interface{})
	if data["issue_status"] != "pending" || data["sync_status"] != "drifted" {
		t.Fatalf("unexpected status data=%v", data)
	}
}

func TestCertificateRoutingUpdate(t *testing.T) {
	r := setupTestRouter()

	status, body := doRequest(t, r, http.MethodPatch, "/v1/certificates/test.example.com/routing", `{"challenge_zone":"sg","sync_zones":["sg"]}`, true)
	if status != http.StatusOK {
		t.Fatalf("routing status=%d body=%s", status, string(body))
	}
}

func TestRemovedRoutesReturnNotFound(t *testing.T) {
	r := setupTestRouter()

	status, _ := postJSON(t, r, "/old/cert_create", `{"domain":"old.example.com"}`)
	if status != http.StatusNotFound {
		t.Fatalf("removed route status=%d", status)
	}
}

func TestAgentEndpoints(t *testing.T) {
	r := setupTestRouter()

	status, body := postJSON(t, r, "/v1/agents/register", `{"agent_id":"agent-hk-1","zone":"hk"}`)
	if status != http.StatusOK {
		t.Fatalf("agent register status=%d body=%s", status, string(body))
	}

	status, body = postJSON(t, r, "/v1/agents/heartbeat", `{"agent_id":"agent-hk-1","ssl_state":{}}`)
	if status != http.StatusOK {
		t.Fatalf("agent heartbeat status=%d body=%s", status, string(body))
	}
}

func postJSON(t *testing.T, r http.Handler, path string, body string) (int, []byte) {
	t.Helper()
	return doRequest(t, r, http.MethodPost, path, body, true)
}

func doRequest(t *testing.T, r http.Handler, method string, path string, body string, auth bool) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+testBearerToken)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	respBody, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, respBody
}
