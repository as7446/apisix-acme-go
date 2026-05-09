package sync

// SyncMode 同步模式
type SyncMode string

const (
	SyncModeStrict SyncMode = "strict"
	SyncModeCompat SyncMode = "compat"
)

// SyncEvent 同步事件
type SyncEvent struct {
	Domain    string `json:"domain"`
	Action    string `json:"action"` // "upsert" | "delete"
	CertPEM   string `json:"cert_pem,omitempty"`
	KeyPEM    string `json:"key_pem,omitempty"`
	Version   int64  `json:"version"`
	Region    string `json:"region,omitempty"`
	Timestamp int64  `json:"timestamp"`
}