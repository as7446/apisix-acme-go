package statestore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
)

const (
	// agentSSLKeyPrefix Redis key 前缀: acme:agent_ssl:{agentID}
	agentSSLKeyPrefix = "acme:agent_ssl:"
	// sslStateTTL Agent SSL 状态 TTL（3 倍心跳间隔）
	sslStateTTL = 3 * 30 * time.Second
)

// RedisAgentStateStore 基于 Redis 的 Agent 状态存储
type RedisAgentStateStore struct {
	client *redis.Client
}

// NewRedisAgentStateStore 创建 Redis 状态存储
func NewRedisAgentStateStore(cfg *config.RedisConfig) (*RedisAgentStateStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  time.Duration(cfg.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("连接 Redis 失败: %w", err)
	}

	return &RedisAgentStateStore{client: client}, nil
}

// NewRedisAgentStateStoreFromClient 用已有 Redis client 创建
func NewRedisAgentStateStoreFromClient(client *redis.Client) *RedisAgentStateStore {
	return &RedisAgentStateStore{client: client}
}

// SaveSSLState 保存 Agent 上报的 SSL 状态（domain → fingerprint）
func (s *RedisAgentStateStore) SaveSSLState(agentID string, state map[string]string) error {
	ctx := context.Background()
	key := agentSSLKeyPrefix + agentID

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)

	if len(state) > 0 {
		fields := make([]string, 0, len(state)*2)
		for domain, fingerprint := range state {
			fields = append(fields, domain, fingerprint)
		}
		pipe.HSet(ctx, key, fields)
		pipe.Expire(ctx, key, sslStateTTL)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// GetSSLState 获取单个 Agent 的 SSL 状态
func (s *RedisAgentStateStore) GetSSLState(agentID string) (map[string]string, error) {
	ctx := context.Background()
	key := agentSSLKeyPrefix + agentID

	result, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetAllSSLState 聚合所有 Agent 的 SSL 状态（用于漂移检测）
// 返回 domain → fingerprint 的聚合 map（如有多 Agent 管理同一域名，取任意一个）
func (s *RedisAgentStateStore) GetAllSSLState() (map[string]string, error) {
	ctx := context.Background()

	// 扫描所有 agent ssl keys
	pattern := agentSSLKeyPrefix + "*"
	merged := make(map[string]string)

	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		states, err := s.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}
		for domain, fingerprint := range states {
			merged[domain] = fingerprint
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("扫描 Agent SSL 状态失败: %w", err)
	}

	return merged, nil
}

// GetAllSSLStateByAgent 获取每个 Agent 的 SSL 状态（用于多 Zone 漂移检测）
// 返回 map[agentID]map[domain]fingerprint
func (s *RedisAgentStateStore) GetAllSSLStateByAgent() (map[string]map[string]string, error) {
	ctx := context.Background()
	pattern := agentSSLKeyPrefix + "*"
	result := make(map[string]map[string]string)
	prefixLen := len(agentSSLKeyPrefix)

	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		agentID := key[prefixLen:]
		states, err := s.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}
		result[agentID] = states
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("扫描 Agent SSL 状态失败: %w", err)
	}

	return result, nil
}

// Close 关闭 Redis 连接
func (s *RedisAgentStateStore) Close() error {
	return s.client.Close()
}
