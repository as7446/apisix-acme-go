package request

// CreateCertRequest 创建证书请求
type CreateCertRequest struct {
	Domain        string   `json:"domain" binding:"required"`
	Email         string   `json:"email"`
	Force         bool     `json:"force"`
	ChallengeZone string   `json:"challenge_zone"`
	SyncZones     []string `json:"sync_zones"`
}

// UpdateCertRoutingRequest 更新证书的 Agent 路由策略
type UpdateCertRoutingRequest struct {
	ChallengeZone string   `json:"challenge_zone"`
	SyncZones     []string `json:"sync_zones"`
}

// ImportDomainRequest 导入单个域名请求
type ImportDomainRequest struct {
	Domain string `json:"domain" binding:"required"`
}
