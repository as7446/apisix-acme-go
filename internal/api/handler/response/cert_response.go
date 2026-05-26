package response

// CertStatusResponse 证书状态响应
type CertStatusResponse struct {
	Domain          string   `json:"domain"`
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
	Total int                  `json:"total"`
	Items []CertStatusResponse `json:"items"`
}
