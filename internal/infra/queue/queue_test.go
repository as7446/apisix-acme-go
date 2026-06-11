package queue

import (
	"sync"
	"testing"
	"time"
)

// TestMemoryQueue_BasicEnqueueDequeue 测试基本入队出队
func TestMemoryQueue_BasicEnqueueDequeue(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	// 入队
	task := &Task{
		ID:     "test-1",
		Type:   TaskIssue,
		Domain: "example.com",
	}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// 检查长度
	if q.Len() != 1 {
		t.Fatalf("Expected len 1, got %d", q.Len())
	}

	// 出队
	dequeued, err := q.Dequeue()
	if err != nil {
		t.Fatalf("Dequeue failed: %v", err)
	}
	if dequeued.ID != "test-1" {
		t.Fatalf("Expected task ID test-1, got %s", dequeued.ID)
	}
	if dequeued.Type != TaskIssue {
		t.Fatalf("Expected task type TaskIssue, got %s", dequeued.Type)
	}
	if dequeued.Domain != "example.com" {
		t.Fatalf("Expected domain example.com, got %s", dequeued.Domain)
	}
}

// TestMemoryQueue_FIFO 测试 FIFO 顺序
func TestMemoryQueue_FIFO(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	// 入队 3 个任务
	for i := 1; i <= 3; i++ {
		task := &Task{
			ID:     "task-" + string(rune('0'+i)),
			Type:   TaskSync,
			Domain: "domain-" + string(rune('0'+i)),
		}
		if err := q.Enqueue(task); err != nil {
			t.Fatalf("Enqueue task-%d failed: %v", i, err)
		}
	}

	// 验证 FIFO 顺序
	for i := 1; i <= 3; i++ {
		dequeued, err := q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue failed at %d: %v", i, err)
		}
		expected := "task-" + string(rune('0'+i))
		if dequeued.ID != expected {
			t.Fatalf("Expected task ID %s, got %s", expected, dequeued.ID)
		}
	}
}

// TestMemoryQueue_Ack 测试 Ack 确认
func TestMemoryQueue_Ack(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	task := &Task{
		ID:     "ack-test",
		Type:   TaskDelete,
		Domain: "ack.example.com",
	}
	q.Enqueue(task)

	// 出队
	dequeued, _ := q.Dequeue()
	if dequeued.ID != "ack-test" {
		t.Fatalf("Expected task ID ack-test, got %s", dequeued.ID)
	}

	// Ack
	if err := q.Ack("ack-test"); err != nil {
		t.Fatalf("Ack failed: %v", err)
	}

	// 长度应该为 0（任务已完成）
	if q.Len() != 0 {
		t.Fatalf("Expected len 0 after Ack, got %d", q.Len())
	}

	// Ack 不存在的任务应该返回错误
	if err := q.Ack("non-existent"); err == nil {
		t.Fatal("Ack should return error for non-existent task")
	}
}

// TestMemoryQueue_Nack 测试 Nack 重新入队
func TestMemoryQueue_Nack(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	task := &Task{
		ID:       "nack-test",
		Type:     TaskIssue,
		Domain:   "nack.example.com",
		Priority: 5, // 初始有优先级
	}
	q.Enqueue(task)

	// 出队
	dequeued, _ := q.Dequeue()

	// Nack - 任务重新入队，优先级归零
	if err := q.Nack("nack-test"); err != nil {
		t.Fatalf("Nack failed: %v", err)
	}

	// 重新出队
	requeued, _ := q.Dequeue()
	if requeued.ID != "nack-test" {
		t.Fatalf("Expected requeued task ID nack-test, got %s", requeued.ID)
	}
	if requeued.Priority != 0 {
		t.Fatalf("Expected priority 0 after Nack, got %d", requeued.Priority)
	}
	if dequeued != requeued {
		t.Fatal("Nack should return the same task object")
	}
}

// TestMemoryQueue_NackNonExistent 测试 Nack 不存在的任务
func TestMemoryQueue_NackNonExistent(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	if err := q.Nack("non-existent"); err == nil {
		t.Fatal("Nack should return error for non-existent task")
	}
}

// TestMemoryQueue_Close 测试关闭队列
func TestMemoryQueue_Close(t *testing.T) {
	q := NewMemoryQueue(100)

	// 关闭队列
	if err := q.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// 再次关闭应该不报错
	if err := q.Close(); err != nil {
		t.Fatalf("Second Close should not return error: %v", err)
	}

	// 关闭后入队应该返回错误
	task := &Task{ID: "after-close"}
	if err := q.Enqueue(task); err == nil {
		t.Fatal("Enqueue after close should return error")
	}

	// 关闭后出队应该返回错误
	if _, err := q.Dequeue(); err == nil {
		t.Fatal("Dequeue after close should return error")
	}
}

// TestMemoryQueue_EmptyDequeue 测试空队列出队（使用超时）
func TestMemoryQueue_EmptyDequeue(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	// 启动一个 goroutine 在短暂延迟后入队
	go func() {
		time.Sleep(50 * time.Millisecond)
		q.Enqueue(&Task{ID: "delayed-task"})
	}()

	// 使用超时出队
	dequeued, err := q.DequeueWithTimeout(1)
	if err != nil {
		t.Fatalf("DequeueWithTimeout failed: %v", err)
	}
	if dequeued == nil {
		t.Fatal("DequeueWithTimeout should return task after delay")
	}
	if dequeued.ID != "delayed-task" {
		t.Fatalf("Expected delayed-task, got %s", dequeued.ID)
	}
}

// TestMemoryQueue_Timeout 测试超时行为
func TestMemoryQueue_Timeout(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	// 空队列超时应该返回 nil
	dequeued, err := q.DequeueWithTimeout(1)
	if err != nil {
		t.Fatalf("DequeueWithTimeout should not return error: %v", err)
	}
	if dequeued != nil {
		t.Fatal("DequeueWithTimeout should return nil on timeout")
	}
}

// TestMemoryQueue_Concurrent 测试并发入队出队
func TestMemoryQueue_Concurrent(t *testing.T) {
	q := NewMemoryQueue(1000)
	defer q.Close()

	var wg sync.WaitGroup
	taskCount := 100

	// 并发入队
	for i := 0; i < taskCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			task := &Task{
				ID:     "concurrent-" + string(rune('a'+id%26)),
				Type:   TaskIssue,
				Domain: "concurrent.example.com",
			}
			q.Enqueue(task)
		}(i)
	}
	wg.Wait()

	// 验证长度
	if q.Len() != taskCount {
		t.Fatalf("Expected len %d, got %d", taskCount, q.Len())
	}

	// 顺序出队并确认
	ackCount := 0
	for i := 0; i < taskCount; i++ {
		task, err := q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue error: %v", err)
		}
		if task != nil {
			q.Ack(task.ID)
			ackCount++
		}
	}

	if ackCount != taskCount {
		t.Fatalf("Expected %d acks, got %d", taskCount, ackCount)
	}
}

// TestMemoryQueue_Priority 测试优先级队列
func TestMemoryQueue_Priority(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	// 入队不同优先级的任务
	tasks := []*Task{
		{ID: "low", Type: TaskSync, Priority: 1},
		{ID: "high", Type: TaskSync, Priority: 10},
		{ID: "medium", Type: TaskSync, Priority: 5},
	}
	for _, task := range tasks {
		q.Enqueue(task)
	}

	// 等待优先级队列消费（正常情况下会合并到主队列）
	time.Sleep(200 * time.Millisecond)

	// 验证所有任务都能出队
	dequeuedCount := 0
	for i := 0; i < 3; i++ {
		task, err := q.DequeueWithTimeout(1)
		if err != nil {
			t.Fatalf("Dequeue error: %v", err)
		}
		if task != nil {
			dequeuedCount++
		}
	}

	if dequeuedCount != 3 {
		t.Fatalf("Expected 3 tasks dequeued, got %d", dequeuedCount)
	}
}

// TestMemoryQueue_EnqueueNilTask 测试入队 nil 任务
func TestMemoryQueue_EnqueueNilTask(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	if err := q.Enqueue(nil); err == nil {
		t.Fatal("Enqueue nil task should return error")
	}
}

// TestMemoryQueue_EnqueueEmptyID 测试入队空 ID 任务
func TestMemoryQueue_EnqueueEmptyID(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	task := &Task{ID: ""}
	if err := q.Enqueue(task); err == nil {
		t.Fatal("Enqueue task with empty ID should return error")
	}
}

// TestMemoryQueue_AckEmptyID 测试 Ack 空 ID
func TestMemoryQueue_AckEmptyID(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	if err := q.Ack(""); err == nil {
		t.Fatal("Ack with empty ID should return error")
	}
}

// TestMemoryQueue_NackEmptyID 测试 Nack 空 ID
func TestMemoryQueue_NackEmptyID(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	if err := q.Nack(""); err == nil {
		t.Fatal("Nack with empty ID should return error")
	}
}

// TestMemoryQueue_DefaultCapacity 测试默认容量
func TestMemoryQueue_DefaultCapacity(t *testing.T) {
	// 传入 0 应该使用默认容量
	q := NewMemoryQueue(0)
	defer q.Close()

	// 验证队列可用
	task := &Task{ID: "default-cap-test"}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
}

// TestMemoryQueue_RunningCount 测试运行中任务计数
func TestMemoryQueue_RunningCount(t *testing.T) {
	q := NewMemoryQueue(100)
	defer q.Close()

	if q.RunningCount() != 0 {
		t.Fatalf("Expected running count 0, got %d", q.RunningCount())
	}

	// 入队并出队
	task := &Task{ID: "running-test"}
	q.Enqueue(task)
	q.Dequeue()

	if q.RunningCount() != 1 {
		t.Fatalf("Expected running count 1, got %d", q.RunningCount())
	}
}

// TestTaskTypes 测试任务类型常量
func TestTaskTypes(t *testing.T) {
	if TaskIssue != "issue" {
		t.Fatalf("Expected TaskIssue=issue, got %s", TaskIssue)
	}
	if TaskSync != "sync" {
		t.Fatalf("Expected TaskSync=sync, got %s", TaskSync)
	}
	if TaskDelete != "delete" {
		t.Fatalf("Expected TaskDelete=delete, got %s", TaskDelete)
	}
}

// TestQueueInterface 测试 Queue 接口（编译时验证）
func TestQueueInterface(t *testing.T) {
	// 这是一个编译时验证，确保 MemoryQueue 实现了 Queue 接口
	var _ Queue = (*MemoryQueue)(nil)
}

// TestPriorityQueue 测试优先级队列内部实现
func TestPriorityQueue(t *testing.T) {
	pq := newPriorityQueue()

	// 测试空队列 Pop
	if pq.Pop() != nil {
		t.Fatal("Pop from empty queue should return nil")
	}

	// 测试空队列长度
	if pq.Len() != 0 {
		t.Fatalf("Expected len 0, got %d", pq.Len())
	}

	// Push 测试
	tasks := []*Task{
		{ID: "p1", Priority: 1},
		{ID: "p3", Priority: 3},
		{ID: "p2", Priority: 2},
	}
	for _, task := range tasks {
		pq.Push(task)
	}

	if pq.Len() != 3 {
		t.Fatalf("Expected len 3, got %d", pq.Len())
	}

	// 验证优先级顺序（高优先级先出）
	first := pq.Pop()
	if first.ID != "p3" {
		t.Fatalf("Expected p3 first (priority 3), got %s", first.ID)
	}

	second := pq.Pop()
	if second.ID != "p2" {
		t.Fatalf("Expected p2 second (priority 2), got %s", second.ID)
	}

	third := pq.Pop()
	if third.ID != "p1" {
		t.Fatalf("Expected p1 third (priority 1), got %s", third.ID)
	}

	if pq.Len() != 0 {
		t.Fatalf("Expected len 0 after pops, got %d", pq.Len())
	}
}
