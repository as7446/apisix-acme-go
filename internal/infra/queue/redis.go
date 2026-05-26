package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// nackScript Lua 脚本：原子执行 HGET + HDEL + LPUSH（Nack 操作）
// KEYS[1] = processing hash key
// KEYS[2] = normal list key
// ARGV[1] = taskID
// 返回: 1=成功, 0=任务不存在
var nackScript = redis.NewScript(`
local data = redis.call('HGET', KEYS[1], ARGV[1])
if not data then
    return 0
end
redis.call('HDEL', KEYS[1], ARGV[1])
local task = cjson.decode(data)
task['priority'] = 0
local newData = cjson.encode(task)
redis.call('LPUSH', KEYS[2], newData)
return 1
`)

// RedisQueue Redis 队列实现
// 使用 Redis List (LPUSH/BRPOP) + Hash (处理中集合) 实现 Queue 接口
type RedisQueue struct {
	client        *redis.Client
	name          string // 队列名称（issue / sync）
	highKey       string // 高优先级 list key
	normalKey     string // 普通 list key
	processingKey string // 处理中 hash key
	closeCh       chan struct{}
	closed        atomic.Bool
}

// NewRedisQueue 创建 Redis 队列
func NewRedisQueue(client *redis.Client, name string, keyPrefix string) *RedisQueue {
	prefix := fmt.Sprintf("%s:%s", keyPrefix, name)
	return &RedisQueue{
		client:        client,
		name:          name,
		highKey:       prefix + ":high",
		normalKey:     prefix + ":normal",
		processingKey: prefix + ":processing",
		closeCh:       make(chan struct{}),
	}
}

// Enqueue 入队
func (rq *RedisQueue) Enqueue(task *Task) error {
	if task == nil {
		return errors.New("task cannot be nil")
	}
	if task.ID == "" {
		return errors.New("task ID cannot be empty")
	}
	if rq.closed.Load() {
		return errors.New("queue is closed")
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task failed: %w", err)
	}

	ctx := context.Background()
	var key string
	if task.Priority > 0 {
		key = rq.highKey
	} else {
		key = rq.normalKey
	}

	if err := rq.client.LPush(ctx, key, data).Err(); err != nil {
		return fmt.Errorf("LPUSH failed: %w", err)
	}

	logger.Log.Debug("任务入队(Redis)", "task_id", task.ID, "type", task.Type, "domain", task.Domain, "queue", rq.name)
	return nil
}

// Dequeue 出队（阻塞直到有任务可用）
func (rq *RedisQueue) Dequeue() (*Task, error) {
	for {
		if rq.closed.Load() {
			return nil, errors.New("queue closed")
		}
		task, err := rq.dequeueOnce(2 * time.Second)
		if err != nil {
			return nil, err
		}
		if task != nil {
			return task, nil
		}
		// timeout, continue loop
	}
}

// DequeueWithTimeout 带超时的出队
func (rq *RedisQueue) DequeueWithTimeout(timeoutSeconds int) (*Task, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	timeout := time.Duration(timeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		if rq.closed.Load() {
			return nil, errors.New("queue closed")
		}

		// 检查关闭信号
		select {
		case <-rq.closeCh:
			return nil, errors.New("queue closed")
		default:
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil // 超时返回 nil，不算错误
		}

		// BRPOP 的超时参数最小支持 1s，剩余时间不足 1s 时用 context 截止时间控制。
		brpopTimeout := 2 * time.Second
		if remaining < brpopTimeout {
			brpopTimeout = remaining
		}
		if brpopTimeout < time.Second {
			brpopTimeout = time.Second
		}
		task, err := rq.dequeueOnceWithContext(ctx, brpopTimeout)
		if err != nil {
			return nil, err
		}
		if task != nil {
			return task, nil
		}
		// BRPOP timeout, check overall deadline
	}
}

// dequeueOnce 执行一次 BRPOP 尝试
func (rq *RedisQueue) dequeueOnce(timeout time.Duration) (*Task, error) {
	return rq.dequeueOnceWithContext(context.Background(), timeout)
}

func (rq *RedisQueue) dequeueOnceWithContext(ctx context.Context, timeout time.Duration) (*Task, error) {
	// BRPOP 按 key 顺序检查，high 优先
	result, err := rq.client.BRPop(ctx, timeout, rq.highKey, rq.normalKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // 超时
		}
		// context cancelled 也视为正常关闭
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil
		}
		return nil, fmt.Errorf("BRPOP failed: %w", err)
	}

	// result[0] = key name, result[1] = value
	if len(result) < 2 {
		return nil, nil
	}

	var task Task
	if err := json.Unmarshal([]byte(result[1]), &task); err != nil {
		return nil, fmt.Errorf("deserialize task failed: %w", err)
	}

	// 存入处理中集合
	if err := rq.client.HSet(ctx, rq.processingKey, task.ID, result[1]).Err(); err != nil {
		// 存入 processing 失败，重新入队以防丢失
		_ = rq.client.LPush(ctx, rq.normalKey, result[1]).Err()
		return nil, fmt.Errorf("HSET processing failed: %w", err)
	}

	logger.Log.Debug("任务出队(Redis)", "task_id", task.ID, "type", task.Type, "domain", task.Domain, "queue", rq.name)
	return &task, nil
}

// Ack 确认任务完成
func (rq *RedisQueue) Ack(taskID string) error {
	if taskID == "" {
		return errors.New("task ID cannot be empty")
	}

	ctx := context.Background()
	deleted, err := rq.client.HDel(ctx, rq.processingKey, taskID).Result()
	if err != nil {
		return fmt.Errorf("HDEL failed: %w", err)
	}
	if deleted == 0 {
		return errors.New("task not found in running state")
	}

	logger.Log.Debug("任务确认完成(Redis)", "task_id", taskID, "queue", rq.name)
	return nil
}

// Nack 任务处理失败，重新入队
func (rq *RedisQueue) Nack(taskID string) error {
	if taskID == "" {
		return errors.New("task ID cannot be empty")
	}

	ctx := context.Background()
	result, err := nackScript.Run(ctx, rq.client, []string{rq.processingKey, rq.normalKey}, taskID).Int()
	if err != nil {
		return fmt.Errorf("Nack script failed: %w", err)
	}
	if result == 0 {
		return errors.New("task not found in running state")
	}

	logger.Log.Debug("任务重新入队(Redis)", "task_id", taskID, "queue", rq.name)
	return nil
}

// Len 返回队列长度（包含高优先级+普通+处理中）
func (rq *RedisQueue) Len() int {
	if rq.closed.Load() {
		return 0
	}

	ctx := context.Background()
	pipe := rq.client.Pipeline()
	highLen := pipe.LLen(ctx, rq.highKey)
	normalLen := pipe.LLen(ctx, rq.normalKey)
	processingLen := pipe.HLen(ctx, rq.processingKey)

	if _, err := pipe.Exec(ctx); err != nil {
		logger.Log.Error("获取队列长度失败", "queue", rq.name, "error", err)
		return 0
	}

	return int(highLen.Val() + normalLen.Val() + processingLen.Val())
}

// Close 关闭队列
func (rq *RedisQueue) Close() error {
	if !rq.closed.CompareAndSwap(false, true) {
		return nil // 已经关闭
	}
	close(rq.closeCh)
	if err := rq.client.Close(); err != nil {
		return fmt.Errorf("close redis client failed: %w", err)
	}
	logger.Log.Info("Redis 队列已关闭", "queue", rq.name)
	return nil
}

// RecoverProcessing 恢复处理中的遗留任务（启动时调用）
// 将 processing hash 中所有任务重新入队到 normal list
func (rq *RedisQueue) RecoverProcessing() error {
	ctx := context.Background()

	tasks, err := rq.client.HGetAll(ctx, rq.processingKey).Result()
	if err != nil {
		return fmt.Errorf("HGETALL processing failed: %w", err)
	}

	if len(tasks) == 0 {
		return nil
	}

	logger.Log.Info("恢复遗留任务", "queue", rq.name, "count", len(tasks))

	for taskID, data := range tasks {
		// 重新入队
		if err := rq.client.LPush(ctx, rq.normalKey, data).Err(); err != nil {
			logger.Log.Error("恢复任务入队失败", "task_id", taskID, "error", err)
			continue
		}
		// 从 processing 中移除
		if err := rq.client.HDel(ctx, rq.processingKey, taskID).Err(); err != nil {
			logger.Log.Error("恢复任务清理失败", "task_id", taskID, "error", err)
		}
	}

	logger.Log.Info("遗留任务恢复完成", "queue", rq.name, "recovered", len(tasks))
	return nil
}
