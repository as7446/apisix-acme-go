package queue

import (
	"errors"
	"sync"
	"time"

	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// MemoryQueue 内存队列实现
// 使用 channel 实现基础 FIFO，通过 priorityQueue 实现优先级
type MemoryQueue struct {
	tasks      chan *Task       // 任务通道（FIFO）
	running    map[string]*Task // 运行中的任务
	mu         sync.RWMutex     // 保护 running 映射
	priorityQ  *priorityQueue   // 优先级队列
	closeCh    chan struct{}    // 关闭信号
	defaultCap int              // 默认容量
}

// NewMemoryQueue 创建内存队列
func NewMemoryQueue(cap int) *MemoryQueue {
	if cap <= 0 {
		cap = 1000
	}
	q := &MemoryQueue{
		tasks:      make(chan *Task, cap),
		running:    make(map[string]*Task),
		priorityQ:  newPriorityQueue(),
		closeCh:    make(chan struct{}),
		defaultCap: cap,
	}
	// 启动优先级队列消费协程
	go q.priorityPump()
	return q
}

// priorityPump 从优先级队列消费并写入主队列
func (q *MemoryQueue) priorityPump() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-q.closeCh:
			return
		case <-ticker.C:
			q.mu.Lock()
			if q.priorityQ.Len() > 0 {
				task := q.priorityQ.Pop()
				if task != nil {
					select {
					case q.tasks <- task:
					default:
						// 队列满，重新放入优先级队列
						q.priorityQ.Push(task)
					}
				}
			}
			q.mu.Unlock()
		}
	}
}

// Enqueue 入队
func (q *MemoryQueue) Enqueue(task *Task) error {
	if task == nil {
		return errors.New("task cannot be nil")
	}
	if task.ID == "" {
		return errors.New("task ID cannot be empty")
	}

	// 检查队列是否已关闭
	select {
	case <-q.closeCh:
		return errors.New("queue is closed")
	default:
	}

	// 优先级任务放入优先级队列
	if task.Priority > 0 {
		q.mu.Lock()
		q.priorityQ.Push(task)
		q.mu.Unlock()
		logger.Log.Debug("任务入队（优先级）", "task_id", task.ID, "type", task.Type, "domain", task.Domain, "priority", task.Priority)
		return nil
	}

	// 普通任务直接入 FIFO 队列
	select {
	case <-q.closeCh:
		return errors.New("queue is closed")
	case q.tasks <- task:
		logger.Log.Debug("任务入队", "task_id", task.ID, "type", task.Type, "domain", task.Domain)
		return nil
	default:
		// 队列满，尝试放入优先级队列
		q.mu.Lock()
		q.priorityQ.Push(task)
		q.mu.Unlock()
		logger.Log.Warn("FIFO队列满，任务移至优先级队列", "task_id", task.ID)
		return nil
	}
}

// Dequeue 出队（阻塞）
func (q *MemoryQueue) Dequeue() (*Task, error) {
	select {
	case <-q.closeCh:
		return nil, errors.New("queue closed")
	case task, ok := <-q.tasks:
		if !ok {
			return nil, errors.New("queue closed")
		}
		q.mu.Lock()
		q.running[task.ID] = task
		q.mu.Unlock()
		logger.Log.Debug("任务出队", "task_id", task.ID, "type", task.Type, "domain", task.Domain)
		return task, nil
	}
}

// DequeueWithTimeout 带超时的出队
func (q *MemoryQueue) DequeueWithTimeout(timeoutSeconds int) (*Task, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	timeout := time.Duration(timeoutSeconds) * time.Second

	select {
	case <-q.closeCh:
		return nil, errors.New("queue closed")
	case task, ok := <-q.tasks:
		if !ok {
			return nil, errors.New("queue closed")
		}
		q.mu.Lock()
		q.running[task.ID] = task
		q.mu.Unlock()
		logger.Log.Debug("任务出队", "task_id", task.ID, "type", task.Type, "domain", task.Domain)
		return task, nil
	case <-time.After(timeout):
		return nil, nil // 超时返回 nil，不算错误
	}
}

// Ack 确认任务完成
func (q *MemoryQueue) Ack(taskID string) error {
	if taskID == "" {
		return errors.New("task ID cannot be empty")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if _, ok := q.running[taskID]; !ok {
		return errors.New("task not found in running state")
	}
	delete(q.running, taskID)
	logger.Log.Debug("任务确认完成", "task_id", taskID)
	return nil
}

// Nack 任务处理失败，重新入队
func (q *MemoryQueue) Nack(taskID string) error {
	if taskID == "" {
		return errors.New("task ID cannot be empty")
	}

	q.mu.Lock()
	task, ok := q.running[taskID]
	if !ok {
		q.mu.Unlock()
		return errors.New("task not found in running state")
	}
	delete(q.running, taskID)
	// 重新入队时降低优先级（避免无限循环）
	task.Priority = 0
	q.mu.Unlock()

	return q.Enqueue(task)
}

// Len 返回队列长度
func (q *MemoryQueue) Len() int {
	select {
	case <-q.closeCh:
		return 0
	default:
	}
	q.mu.RLock()
	priorityLen := q.priorityQ.Len()
	runningLen := len(q.running)
	q.mu.RUnlock()

	return len(q.tasks) + priorityLen + runningLen
}

// Close 关闭队列
func (q *MemoryQueue) Close() error {
	select {
	case <-q.closeCh:
		return nil // 已经关闭
	default:
	}
	close(q.closeCh)

	q.mu.Lock()
	// 清空运行中的任务
	q.running = make(map[string]*Task)
	// 清空优先级队列
	q.priorityQ = newPriorityQueue()
	q.mu.Unlock()

	// 关闭主通道
	close(q.tasks)

	logger.Log.Info("内存队列已关闭")
	return nil
}

// RunningCount 返回正在运行的任务数
func (q *MemoryQueue) RunningCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.running)
}

// ============================================================
// 优先级队列实现（基于堆）
// ============================================================

// priorityQueue 最小堆实现的优先级队列
type priorityQueue struct {
	items []*Task
	mu    sync.RWMutex
}

func newPriorityQueue() *priorityQueue {
	return &priorityQueue{
		items: make([]*Task, 0),
	}
}

func (pq *priorityQueue) Len() int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	return len(pq.items)
}

func (pq *priorityQueue) Push(task *Task) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	pq.items = append(pq.items, task)
	pq.bubbleUp(len(pq.items) - 1)
}

func (pq *priorityQueue) Pop() *Task {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.items) == 0 {
		return nil
	}

	item := pq.items[0]
	last := len(pq.items) - 1
	pq.items[0] = pq.items[last]
	pq.items = pq.items[:last]
	if len(pq.items) > 0 {
		pq.bubbleDown(0)
	}
	return item
}

func (pq *priorityQueue) bubbleUp(idx int) {
	for idx > 0 {
		parent := (idx - 1) / 2
		// 优先级高的（数值大）在上
		if pq.items[idx].Priority <= pq.items[parent].Priority {
			break
		}
		pq.items[idx], pq.items[parent] = pq.items[parent], pq.items[idx]
		idx = parent
	}
}

func (pq *priorityQueue) bubbleDown(idx int) {
	length := len(pq.items)
	for {
		left := 2*idx + 1
		right := 2*idx + 2
		largest := idx

		if left < length && pq.items[left].Priority > pq.items[largest].Priority {
			largest = left
		}
		if right < length && pq.items[right].Priority > pq.items[largest].Priority {
			largest = right
		}
		if largest == idx {
			break
		}
		pq.items[idx], pq.items[largest] = pq.items[largest], pq.items[idx]
		idx = largest
	}
}
