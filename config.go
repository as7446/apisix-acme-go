package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen           string `yaml:"listen"`
	BearerToken      string `yaml:"bearer_token"`
	ApisixAdminURL   string `yaml:"apisix_admin_url"`
	ApisixAdminToken string `yaml:"apisix_admin_token"`
	DefaultEmail     string `yaml:"default_email"`
	StorageDir       string `yaml:"storage_dir"`
	RenewCron        string `yaml:"renew_cron"`
	RenewBeforeDays  int    `yaml:"renew_before_days"` // 证书到期前多少天开始续期
	// ACME 配置
	AcmeDirectoryURL string            `yaml:"acme_directory_url"`
	AcmeDNSProvider  string            `yaml:"acme_dns_provider"`
	AcmeDNSEnv       map[string]string `yaml:"acme_dns_env"`
	// ChallengeRoute HTTP-01 验证路由配置
	ChallengeRoute ChallengeRouteConfig `yaml:"challenge_route"`
}

type ChallengeRouteConfig struct {
	Enable         bool     `yaml:"enable"`
	RouteID        string   `yaml:"route_id"`
	Hosts          []string `yaml:"hosts"`
	UpstreamNodes  []string `yaml:"upstream_nodes"`
	UpstreamScheme string   `yaml:"upstream_scheme"`
	Priority       int      `yaml:"priority"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// 设置默认值
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.StorageDir == "" {
		cfg.StorageDir = "out"
	}
	if cfg.RenewCron == "" {
		cfg.RenewCron = "0 0 3 * * *"
	}
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = 30 // 默认提前 30 天续期
	}
	if cfg.AcmeDirectoryURL == "" {
		cfg.AcmeDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if cfg.ChallengeRoute.RouteID == "" {
		cfg.ChallengeRoute.RouteID = "apisix_acme_http01"
	}
	if cfg.ChallengeRoute.UpstreamScheme == "" {
		cfg.ChallengeRoute.UpstreamScheme = "http"
	}
	return &cfg, nil
}
