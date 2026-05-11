package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
)

var (
	hostname = getHostname()
	agentID  = fmt.Sprintf("%s-%s", hostname, generateShortID())
)

func main() {
	controllerURL := flag.String("controller", "http://localhost:8080", "Controller URL")
	zone := flag.String("zone", "default", "Agent zone")
	version := flag.String("version", "1.0.0", "Agent version")
	capabilities := flag.String("capabilities", "apisix,http_challenge", "Agent capabilities (comma-separated)")
	flag.Parse()

	capabilityList := parseCapabilities(*capabilities)

	fmt.Printf("=== Agent 启动 ===\n")
	fmt.Printf("Agent ID: %s\n", agentID)
	fmt.Printf("Zone: %s\n", *zone)
	fmt.Printf("Controller: %s\n", *controllerURL)
	fmt.Printf("Capabilities: %v\n", capabilityList)

	// 创建客户端并注册
	client := NewAgentClient(*controllerURL)

	registerReq := &RegisterRequest{
		AgentID:      agentID,
		Zone:         *zone,
		Hostname:     hostname,
		IP:           getIP(),
		Version:      *version,
		Capabilities: capabilityList,
	}

	resp, err := client.Register(registerReq)
	if err != nil {
		fmt.Printf("❌ 注册失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ 注册成功，心跳间隔: %d 秒\n", resp.HeartbeatInterval)

	// 启动心跳循环
	stopCh := make(chan struct{})
	go heartbeatLoop(client, agentID, resp.HeartbeatInterval, stopCh)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Printf("\n=== Agent 关闭 ===\n")
	close(stopCh)
	time.Sleep(time.Second)
	fmt.Printf("再见！\n")
}

func heartbeatLoop(client *AgentClient, agentID string, interval int, stopCh <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if err := client.Heartbeat(agentID); err != nil {
				fmt.Printf("❌ 心跳失败: %v\n", err)
			} else {
				fmt.Printf("💓 心跳发送成功\n")
			}
		}
	}
}

func parseCapabilities(s string) []string {
	var caps []string
	for _, c := range splitComma(s) {
		c = trimSpace(c)
		if c != "" {
			caps = append(caps, c)
		}
	}
	return caps
}

func splitComma(s string) []string {
	var result []string
	var current string
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getIP() string {
	// 简化实现，返回空字符串
	// 实际应该获取本机 IP
	return ""
}

func generateShortID() string {
	id, err := uuid.New().MarshalText()
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return string(id)[:8]
}
