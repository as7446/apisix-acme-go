package handler

import (
	"errors"

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
	result, err := h.certSvc.List(c.Request.Context())
	if err != nil {
		response.InternalError(c, err.Error())
		return
	}

	items := make([]response.CertStatusResponse, len(result))
	for i, r := range result {
		items[i] = response.CertStatusResponse{
			Domain:          r.Domain,
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
			CreatedAt:       r.CreatedAt,
			UpdatedAt:       r.UpdatedAt,
		}
	}

	c.JSON(200, response.Response{
		Code: 200,
		Data: response.CertListResponse{
			Total: len(items),
			Items: items,
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

func certStatusFromResult(r *application.CertStatusResult) response.CertStatusResponse {
	return response.CertStatusResponse{
		Domain:          r.Domain,
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
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
