package main

import (
	"fmt"
	"os"

	agentpkg "github.com/as7446/apisix-acme-go/internal/agent"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	if cfg.LogLevel != "" {
		logger.Init(cfg.LogLevel)
	}

	switch {
	case cfg.IsAgent():
		// Agent 模式
		runner := agentpkg.NewRunner(cfg)
		if err := runner.Run(); err != nil {
			logger.Log.Error("Agent 启动失败", "error", err)
			os.Exit(1)
		}
	default:
		// Controller 模式
		runController(cfg)
	}
}
