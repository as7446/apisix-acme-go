package queue

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// TaskType 任务类型
type TaskType string

const (
	TaskIssue  TaskType = "issue"  // 证书签发任务
	TaskSync   TaskType = "sync"   // 同步任务
	TaskDelete TaskType = "delete" // 删除任务
)

// Task 队列任务
type Task struct {
	ID        string                 `json:"id"`         // 任务唯一标识
	Type      TaskType               `json:"type"`       // 任务类型
	Domain    string                 `json:"domain"`     // 关联域名
	Priority  int                    `json:"priority"`   // 优先级（数值越大优先级越高）
	CreatedAt int64                  `json:"created_at"` // 创建时间戳
	Payload   map[string]interface{} `json:"payload"`    // 任务负载数据
}

// Queue 队列接口
type Queue interface {
	// Enqueue 入队
	Enqueue(task *Task) error
	// Dequeue 出队（阻塞直到有任务可用）
	Dequeue() (*Task, error)
	// DequeueWithTimeout 带超时的出队
	DequeueWithTimeout(timeoutSeconds int) (*Task, error)
	// Ack 确认任务完成
	Ack(taskID string) error
	// Nack 任务处理失败，重新入队
	Nack(taskID string) error
	// Len 返回队列长度
	Len() int
	// Close 关闭队列
	Close() error
}

// NewQueue 创建队列实例
// name 用于区分逻辑队列（如 "issue"、"sync"），在 Redis 模式下作为 key 前缀的一部分
func NewQueue(cfg *config.Config, name string) (Queue, error) {
	switch cfg.QueueType {
	case "redis":
		return newRedisQueue(cfg, name)
	case "", "memory":
		return NewMemoryQueue(cfg.QueueCapacity), nil
	default:
		return nil, fmt.Errorf("unsupported queue_type: %s", cfg.QueueType)
	}
}

// newRedisQueue 创建 Redis 队列实例
func newRedisQueue(cfg *config.Config, name string) (*RedisQueue, error) {
	opts := &redis.Options{
		Addr:         cfg.Redis.Addr,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		DialTimeout:  time.Duration(cfg.Redis.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.Redis.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Redis.WriteTimeout) * time.Second,
	}

	client := redis.NewClient(opts)

	// Ping 验证连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Redis.DialTimeout)*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed (addr=%s): %w", cfg.Redis.Addr, err)
	}

	rq := NewRedisQueue(client, name, cfg.Redis.KeyPrefix)
	logger.Log.Info("Redis 队列已创建", "queue", name, "addr", cfg.Redis.Addr, "prefix", cfg.Redis.KeyPrefix)
	return rq, nil
}
