package worker

import (
	"context"
	"fmt"
	"sync"

	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/queue"
)

// HandlerFunc worker 处理函数
type HandlerFunc func(ctx context.Context, task *queue.Task) error

// Pool 通用 worker pool
type Pool struct {
	name    string
	queue   queue.Queue
	handler HandlerFunc
	workers int
	timeout int // dequeue 超时秒数

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewPool 创建 worker pool
func NewPool(name string, q queue.Queue, handler HandlerFunc, workers, timeout int) *Pool {
	return &Pool{
		name:    name,
		queue:   q,
		handler: handler,
		workers: workers,
		timeout: timeout,
	}
}

// Start 启动 N 个 worker goroutine
func (p *Pool) Start(ctx context.Context) {
	p.ctx, p.cancel = context.WithCancel(ctx)

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.runWorker(i)
	}

	logger.Log.Info(fmt.Sprintf("[%s] worker pool 已启动", p.name),
		"workers", p.workers, "timeout", p.timeout)
}

// Stop 停止 worker pool（等待所有 worker 退出）
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	logger.Log.Info(fmt.Sprintf("[%s] worker pool 已停止", p.name))
}

// runWorker 单个 worker 主循环
func (p *Pool) runWorker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		task, err := p.queue.DequeueWithTimeout(p.timeout)
		if err != nil {
			logger.Log.Error(fmt.Sprintf("[%s] worker-%d dequeue 错误", p.name, id), "error", err)
			continue
		}
		if task == nil {
			// 超时无任务，继续循环
			continue
		}

		// 执行 handler
		if err := p.handler(p.ctx, task); err != nil {
			logger.Log.Error(fmt.Sprintf("[%s] worker-%d 处理失败", p.name, id),
				"domain", task.Domain, "error", err)
			_ = p.queue.Nack(task.ID)
		} else {
			_ = p.queue.Ack(task.ID)
		}
	}
}
