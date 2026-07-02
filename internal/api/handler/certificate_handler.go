package handler

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler/request"
	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
	"github.com/as7446/apisix-acme-go/internal/application"
)

// CertificateHandler RESTful 证书 API 处理器
type CertificateHandler struct {
	commandSvc *application.CertCommandService
	certSvc    *application.CertService
}

// NewCertificateHandler 创建 CertificateHandler
func NewCertificateHandler(commandSvc *application.CertCommandService, certSvc *application.CertService) *CertificateHandler {
	return &CertificateHandler{commandSvc: commandSvc, certSvc: certSvc}
}

// Create 创建证书
// POST /v1/certificates
func (h *CertificateHandler) Create(c *gin.Context) {
	var req request.CreateCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err)
		return
	}

	result, err := h.commandSvc.CreateCert(c.Request.Context(), req.Domain, req.Email, req.Force, req.ChallengeZone, req.SyncZones)
	if err != nil {
		if errors.Is(err, application.ErrCertExists) {
			c.JSON(200, response.Response{
				Code:    200,
				Message: "证书已存在且未过期",
				Data:    certStatusFromResult(result),
			})
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(201, response.Response{
		Code:    201,
		Message: "证书申请已创建",
		Data:    certStatusFromResult(result),
	})
}

// List 获取证书列表
// GET /v1/certificates
func (h *CertificateHandler) List(c *gin.Context) {
	query := application.CertListQuery{
		Page:            intQuery(c, "page", 1),
		PageSize:        intQuery(c, "page_size", 10),
		Keyword:         c.Query("q"),
		ExpireStatus:    c.Query("expire_status"),
		LifecycleStatus: c.Query("lifecycle_status"),
		IssueStatus:     c.Query("issue_status"),
		SyncStatus:      c.Query("sync_status"),
		Source:          c.Query("source"),
		SyncZone:        c.Query("sync_zone"),
		IncludeDeleted:  boolQuery(c, "include_deleted", false),
	}

	result, err := h.certSvc.ListPage(c.Request.Context(), query)
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	items := make([]response.CertStatusResponse, len(result.Items))
	for i, r := range result.Items {
		items[i] = response.CertStatusResponse{
			ID:              r.ID,
			Domain:          r.Domain,
			APISIXID:        r.APISIXID,
			Source:          string(r.Source),
			LifecycleStatus: string(r.LifecycleStatus),
			IssueStatus:     string(r.IssueStatus),
			SyncStatus:      string(r.SyncStatus),
			NotBefore:       r.NotBefore,
			NotAfter:        r.NotAfter,
			Revision:        r.Revision,
			Fingerprint:     r.Fingerprint,
			SerialNumber:    r.SerialNumber,
			ErrorMessage:    r.ErrorMessage,
			RetryCount:      r.RetryCount,
			NextRetryAt:     r.NextRetryAt,
			ChallengeZone:   r.ChallengeZone,
			SyncZones:       r.SyncZones,
			LastIssuedAt:    r.LastIssuedAt,
			LastRenewAt:     r.LastRenewAt,
			LastSyncedAt:    r.LastSyncedAt,
			CreatedAt:       r.CreatedAt,
			UpdatedAt:       r.UpdatedAt,
		}
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: response.CertListResponse{
			Total:    result.Total,
			Page:     result.Page,
			PageSize: result.PageSize,
			Items:    items,
		},
	})
}

// Get 获取单个证书状态
// GET /v1/certificates/:domain
func (h *CertificateHandler) Get(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	result, err := h.certSvc.GetStatus(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: response.CertStatusResponse{
			Domain:          result.Domain,
			LifecycleStatus: string(result.LifecycleStatus),
			IssueStatus:     string(result.IssueStatus),
			SyncStatus:      string(result.SyncStatus),
			NotBefore:       result.NotBefore,
			NotAfter:        result.NotAfter,
			Revision:        result.Revision,
			Fingerprint:     result.Fingerprint,
			SerialNumber:    result.SerialNumber,
			ErrorMessage:    result.ErrorMessage,
			RetryCount:      result.RetryCount,
			NextRetryAt:     result.NextRetryAt,
			ChallengeZone:   result.ChallengeZone,
			SyncZones:       result.SyncZones,
			CreatedAt:       result.CreatedAt,
			UpdatedAt:       result.UpdatedAt,
		},
	})
}

// Delete 删除证书
// DELETE /v1/certificates/:domain
func (h *CertificateHandler) Delete(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	err := h.certSvc.Delete(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: "证书已删除",
	})
}

// UpdateRouting 更新证书的 Agent 路由策略
// PATCH /v1/certificates/:domain/routing
func (h *CertificateHandler) UpdateRouting(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	var req request.UpdateCertRoutingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err)
		return
	}

	result, err := h.certSvc.UpdateRouting(c.Request.Context(), domain, req.ChallengeZone, req.SyncZones)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: "证书路由策略已更新",
		Data:    certStatusFromResult(result),
	})
}

// Retry 手动重试失败的证书
// POST /v1/certificates/:domain/retry
func (h *CertificateHandler) Retry(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	result, err := h.commandSvc.RetryCert(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: "重试已触发",
		Data:    certStatusFromResult(result),
	})
}

// Renew 手动续期证书
// POST /v1/certificates/:domain/renew
func (h *CertificateHandler) Renew(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	result, err := h.commandSvc.RenewCert(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: "续期已触发",
		Data:    certStatusFromResult(result),
	})
}

// Sync 手动同步证书到 Agent/APISIX
// POST /v1/certificates/:domain/sync
func (h *CertificateHandler) Sync(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	result, err := h.certSvc.Sync(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	c.JSON(200, response.Response{
		Code:    200,
		Message: "同步完成",
		Data:    certStatusFromResult(result),
	})
}

// Versions 获取证书版本列表
// GET /v1/certificates/:domain/versions
func (h *CertificateHandler) Versions(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		response.BadRequest(c, errors.New("domain is required"))
		return
	}

	versions, err := h.certSvc.ListVersions(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "证书不存在")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	items := make([]response.CertVersionResponse, 0, len(versions))
	for _, v := range versions {
		items = append(items, response.CertVersionResponse{
			ID:           v.ID,
			CertID:       v.CertID,
			Revision:     v.Revision,
			NotBefore:    v.NotBefore,
			NotAfter:     v.NotAfter,
			Fingerprint:  v.Fingerprint,
			SerialNumber: v.SerialNumber,
			CreatedAt:    v.CreatedAt,
		})
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: response.CertVersionListResponse{Items: items},
	})
}

func certStatusFromResult(r *application.CertStatusResult) response.CertStatusResponse {
	return response.CertStatusResponse{
		ID:              r.ID,
		Domain:          r.Domain,
		APISIXID:        r.APISIXID,
		Source:          string(r.Source),
		LifecycleStatus: string(r.LifecycleStatus),
		IssueStatus:     string(r.IssueStatus),
		SyncStatus:      string(r.SyncStatus),
		NotBefore:       r.NotBefore,
		NotAfter:        r.NotAfter,
		Revision:        r.Revision,
		Fingerprint:     r.Fingerprint,
		SerialNumber:    r.SerialNumber,
		ErrorMessage:    r.ErrorMessage,
		RetryCount:      r.RetryCount,
		NextRetryAt:     r.NextRetryAt,
		ChallengeZone:   r.ChallengeZone,
		SyncZones:       r.SyncZones,
		LastIssuedAt:    r.LastIssuedAt,
		LastRenewAt:     r.LastRenewAt,
		LastSyncedAt:    r.LastSyncedAt,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

func intQuery(c *gin.Context, key string, fallback int) int {
	raw := c.Query(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func boolQuery(c *gin.Context, key string, fallback bool) bool {
	raw := c.Query(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}
