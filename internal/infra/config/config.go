package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

const (
	// RenewLockTimeout 续期锁超时时间（秒）
	RenewLockTimeout = 3600 // 1 小时
	// RSAKeyBits RSA 密钥位数
	RSAKeyBits = 2048
	// CacheExpiryBuffer 缓存过期缓冲（秒，提前 1 天视为过期）
	CacheExpiryBuffer = 86400
)

// Config 应用配置
type Config struct {
	// 运行模式：controller / agent（默认 controller）
	Mode string `yaml:"mode"`

	Listen           string `yaml:"listen"`
	BearerToken      string `yaml:"bearer_token"`
	ApisixAdminURL   string `yaml:"apisix_admin_url"`
	ApisixAdminToken string `yaml:"apisix_admin_token"`
	DefaultEmail     string `yaml:"default_email"`

	RenewCron       string `yaml:"renew_cron"`
	RenewBeforeDays int    `yaml:"renew_before_days"`
	DriftCron       string `yaml:"drift_cron"`
	ManagedByLabel  string `yaml:"managed_by_label"` // Label value written to APISIX SSL resources to identify managed certs

	// 数据库配置
	DB DBConfig `yaml:"db"`

	// 存储配置
	Storage StorageConfig `yaml:"storage"`

	// Client/Server Config
	HTTPTimeout        int `yaml:"http_timeout"`         // HTTP Client Timeout (seconds)
	ServerReadTimeout  int `yaml:"server_read_timeout"`  // Server Read Timeout (seconds)
	ServerWriteTimeout int `yaml:"server_write_timeout"` // Server Write Timeout (seconds)

	// ACME 配置
	AcmeDirectoryURL string            `yaml:"acme_directory_url"`
	AcmeDNSProvider  string            `yaml:"acme_dns_provider"`
	AcmeDNSEnv       map[string]string `yaml:"acme_dns_env"`
	// ChallengeRoute HTTP-01 验证路由配置
	ChallengeRoute ChallengeRouteConfig `yaml:"challenge_route"`

	// Worker Pool 配置
	IssueWorkers         int    `yaml:"issue_workers"`          // 签发 worker 数（默认 3）
	QueueCapacity        int    `yaml:"queue_capacity"`         // 队列容量（默认 1000）
	QueueType            string `yaml:"queue_type"`             // 队列类型: memory（默认）| redis
	WorkerDequeueTimeout int    `yaml:"worker_dequeue_timeout"` // worker 出队超时秒数（默认 5）
	RecoveryCron         string `yaml:"recovery_cron"`          // 恢复扫描 cron（默认 "0 */5 * * * *"）

	// Redis 配置（queue_type=redis 时生效）
	Redis RedisConfig `yaml:"redis"`

	// 证书申请重试配置
	CertRetryMax      int `yaml:"cert_retry_max"`      // 证书申请最大重试次数（默认 3）
	CertRetryDelay    int `yaml:"cert_retry_delay"`    // 首次重试延迟秒数（默认 60，后续指数增长）
	CertCooldownHours int `yaml:"cert_cooldown_hours"` // 达到最大重试后冷却时间（小时，默认 24）

	// 日志级别（debug / info / warn / error）
	LogLevel string `yaml:"log_level"`

	// Agent 长轮询超时秒数（默认 30）
	LongPollTimeout int `yaml:"long_poll_timeout"`
	// Agent 任务超时秒数（默认 300）
	AgentTaskTimeout int `yaml:"agent_task_timeout"`

	// Agent 模式配置
	ControllerURL string `yaml:"controller_url"`
	AgentID       string `yaml:"agent_id"` // Agent 唯一标识，留空则使用 hostname
	AgentRegion   string `yaml:"agent_region"`

	// 访问日志跳过路径前缀列表（匹配的路径不记录访问日志）
	AccessLogSkipPrefixes []string `yaml:"access_log_skip_prefixes"`
}

// DBConfig 数据库配置
type DBConfig struct {
	Dsn             string `yaml:"dsn"`               // 数据源名称，如 user:password@tcp(host:port)/dbname?charset=utf8mb4
	MaxOpenConns    int    `yaml:"max_open_conns"`    // 最大打开连接数（默认 100）
	MaxIdleConns    int    `yaml:"max_idle_conns"`    // 最大空闲连接数（默认 10）
	ConnMaxLifetime int    `yaml:"conn_max_lifetime"` // 连接最大存活时间（秒，默认 3600）
	TablePrefix     string `yaml:"table_prefix"`      // 表名前缀（默认 cert_）
}

// ChallengeRouteConfig HTTP-01 验证路由配置
type ChallengeRouteConfig struct {
	Enable         bool     `yaml:"enable"`
	RouteName      string   `yaml:"route_name"`
	Hosts          []string `yaml:"hosts"`
	UpstreamNodes  []string `yaml:"upstream_nodes"`
	UpstreamScheme string   `yaml:"upstream_scheme"`
	Priority       int      `yaml:"priority"`
}

// StorageConfig 存储配置
type StorageConfig struct {
	Local struct {
		BasePath string `yaml:"base_path"` // 基础路径，默认为 "certs"
	} `yaml:"local"`
}

// RedisConfig Redis 连接配置
type RedisConfig struct {
	Addr         string `yaml:"addr"`          // 地址，如 "127.0.0.1:6379"
	Password     string `yaml:"password"`      // 密码（空=无认证）
	DB           int    `yaml:"db"`            // DB 编号（默认 0）
	KeyPrefix    string `yaml:"key_prefix"`    // key 前缀（默认 "acme:queue"）
	PoolSize     int    `yaml:"pool_size"`     // 连接池大小（默认 10）
	DialTimeout  int    `yaml:"dial_timeout"`  // 连接超时秒数（默认 5）
	ReadTimeout  int    `yaml:"read_timeout"`  // 读超时秒数（默认 3）
	WriteTimeout int    `yaml:"write_timeout"` // 写超时秒数（默认 3）
}

// IsController 当前是否为 Controller 模式
func (c *Config) IsController() bool {
	return c.Mode == "" || c.Mode == "controller"
}

// IsAgent 当前是否为 Agent 模式
func (c *Config) IsAgent() bool {
	return c.Mode == "agent"
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.Storage.Local.BasePath == "" {
		cfg.Storage.Local.BasePath = "certs"
	}
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = 30
	}
	if cfg.RenewCron == "" {
		cfg.RenewCron = "0 0 2 * * *"
	}
	if cfg.DriftCron == "" {
		cfg.DriftCron = "0 0 * * * *"
	}
	if cfg.ManagedByLabel == "" {
		cfg.ManagedByLabel = "apisix-acme-go"
	}
	if cfg.AcmeDirectoryURL == "" {
		cfg.AcmeDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if cfg.ChallengeRoute.RouteName == "" {
		cfg.ChallengeRoute.RouteName = "apisix_acme_http01"
	}
	if cfg.ChallengeRoute.UpstreamScheme == "" {
		cfg.ChallengeRoute.UpstreamScheme = "http"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15
	}
	if cfg.ServerReadTimeout <= 0 {
		cfg.ServerReadTimeout = 15
	}
	if cfg.ServerWriteTimeout <= 0 {
		cfg.ServerWriteTimeout = 30
	}
	if cfg.IssueWorkers <= 0 {
		cfg.IssueWorkers = 3
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 1000
	}
	if cfg.WorkerDequeueTimeout <= 0 {
		cfg.WorkerDequeueTimeout = 5
	}
	if cfg.RecoveryCron == "" {
		cfg.RecoveryCron = "0 */5 * * * *"
	}
	if cfg.CertRetryMax <= 0 {
		cfg.CertRetryMax = 3
	}
	if cfg.CertRetryDelay <= 0 {
		cfg.CertRetryDelay = 60
	}
	if cfg.CertCooldownHours <= 0 {
		cfg.CertCooldownHours = 24
	}
	if cfg.LongPollTimeout <= 0 {
		cfg.LongPollTimeout = 30
	}
	// 确保 WriteTimeout > LongPollTimeout，否则长轮询期间服务端会超时断开连接导致 Agent EOF
	if cfg.ServerWriteTimeout <= cfg.LongPollTimeout {
		cfg.ServerWriteTimeout = cfg.LongPollTimeout + 10
	}
	if cfg.AgentTaskTimeout <= 0 {
		cfg.AgentTaskTimeout = 300
	}
	// 访问日志默认跳过高频 Agent 接口（除注册外）
	// 规则：以 * 结尾表示前缀匹配，否则精确匹配
	if len(cfg.AccessLogSkipPrefixes) == 0 {
		cfg.AccessLogSkipPrefixes = []string{
			"/v1/agents/heartbeat",
			"/v1/agents/task_report",
			"/v1/agents/VM*",
			"/v1/agents/agent*",
			"/healthz",
		}
	}
	// Queue 默认值
	if cfg.QueueType == "" {
		cfg.QueueType = "memory"
	}
	// Redis 默认值
	if cfg.Redis.KeyPrefix == "" {
		cfg.Redis.KeyPrefix = "acme:queue"
	}
	if cfg.Redis.PoolSize <= 0 {
		cfg.Redis.PoolSize = 10
	}
	if cfg.Redis.DialTimeout <= 0 {
		cfg.Redis.DialTimeout = 5
	}
	if cfg.Redis.ReadTimeout <= 0 {
		cfg.Redis.ReadTimeout = 3
	}
	if cfg.Redis.WriteTimeout <= 0 {
		cfg.Redis.WriteTimeout = 3
	}
	// DB 默认值
	if cfg.DB.MaxOpenConns <= 0 {
		cfg.DB.MaxOpenConns = 100
	}
	if cfg.DB.MaxIdleConns <= 0 {
		cfg.DB.MaxIdleConns = 10
	}
	if cfg.DB.ConnMaxLifetime <= 0 {
		cfg.DB.ConnMaxLifetime = 3600
	}
	if cfg.DB.TablePrefix == "" {
		cfg.DB.TablePrefix = "cert_"
	}
}
