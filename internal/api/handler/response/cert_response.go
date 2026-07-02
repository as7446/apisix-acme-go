package response

// CertStatusResponse 证书状态响应
type CertStatusResponse struct {
	ID              int      `json:"id"`
	Domain          string   `json:"domain"`
	APISIXID        string   `json:"apisix_id,omitempty"`
	Source          string   `json:"source,omitempty"`
	LifecycleStatus string   `json:"lifecycle_status"`
	IssueStatus     string   `json:"issue_status"`
	SyncStatus      string   `json:"sync_status"`
	NotBefore       int64    `json:"not_before"`
	NotAfter        int64    `json:"not_after"`
	Revision        int64    `json:"revision"`
	Fingerprint     string   `json:"fingerprint,omitempty"`
	SerialNumber    string   `json:"serial_number,omitempty"`
	ErrorMessage    string   `json:"error_message,omitempty"`
	RetryCount      int      `json:"retry_count"`
	NextRetryAt     int64    `json:"next_retry_at,omitempty"`
	ChallengeZone   string   `json:"challenge_zone,omitempty"`
	SyncZones       []string `json:"sync_zones,omitempty"`
	LastIssuedAt    int64    `json:"last_issued_at,omitempty"`
	LastRenewAt     int64    `json:"last_renew_at,omitempty"`
	LastSyncedAt    int64    `json:"last_synced_at,omitempty"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

// CertCreateResponse 创建证书响应
type CertCreateResponse struct {
	Domain      string `json:"domain"`
	IssueStatus string `json:"issue_status"`
	Source      string `json:"source"`
	CreatedAt   int64  `json:"created_at"`
}

// CertListResponse 证书列表响应
type CertListResponse struct {
	Total    int64                `json:"total"`
	Page     int                  `json:"page,omitempty"`
	PageSize int                  `json:"page_size,omitempty"`
	Items    []CertStatusResponse `json:"items"`
}

type CertVersionResponse struct {
	ID           int    `json:"id"`
	CertID       int    `json:"cert_id"`
	Revision     int64  `json:"revision"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

type CertVersionListResponse struct {
	Items []CertVersionResponse `json:"items"`
}
