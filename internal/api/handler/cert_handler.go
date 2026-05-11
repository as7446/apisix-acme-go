package handler

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/as7446/apisix-acme-go/internal/api/handler/response"
	"github.com/as7446/apisix-acme-go/internal/application"
)

// CertHandler Cert API 处理
type CertHandler struct {
	svc *application.CertService
}

// NewCertHandler 创建 CertHandler
func NewCertHandler(svc *application.CertService) *CertHandler {
	return &CertHandler{svc: svc}
}

// Info 获取证书信息
// GET /apisix_acme/cert_info
func (h *CertHandler) Info(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		response.BadRequest(c, nil)
		return
	}

	result, err := h.svc.GetInfo(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "未找到证书")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	response.SuccessWithMessage(c, result, "获取证书信息成功")
}

// Delete 删除证书
// DELETE /apisix_acme/cert_delete
func (h *CertHandler) Delete(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		response.BadRequest(c, nil)
		return
	}

	err := h.svc.Delete(c.Request.Context(), domain)
	if err != nil {
		if errors.Is(err, application.ErrCertNotFound) {
			response.NotFound(c, "未找到证书")
			return
		}
		response.InternalError(c, err.Error())
		return
	}

	response.SuccessWithMessage(c, nil, "已删除")
}
