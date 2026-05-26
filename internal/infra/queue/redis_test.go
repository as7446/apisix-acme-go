package queue

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestRedisQueue(t *testing.T, name string) (*RedisQueue, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	rq := NewRedisQueue(client, name, "test:queue")
	return rq, mr
}

func TestRedisQueue_EnqueueDequeue(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	task := &Task{
		ID:        "task-1",
		Type:      TaskIssue,
		Domain:    "example.com",
		Priority:  0,
		CreatedAt: time.Now().Unix(),
		Payload:   map[string]interface{}{"action": "issue"},
	}

	// Enqueue
	if err := rq.Enqueue(task); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Len should be 1
	if rq.Len() != 1 {
		t.Fatalf("expected Len=1, got %d", rq.Len())
	}

	// Dequeue
	got, err := rq.DequeueWithTimeout(1)
	if err != nil {
		t.Fatalf("DequeueWithTimeout failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected task, got nil")
	}
	if got.ID != "task-1" {
		t.Fatalf("expected task ID 'task-1', got '%s'", got.ID)
	}
	if got.Domain != "example.com" {
		t.Fatalf("expected domain 'example.com', got '%s'", got.Domain)
	}

	// After dequeue, task should be in processing (Len includes processing)
	if rq.Len() != 1 {
		t.Fatalf("expected Len=1 (in processing), got %d", rq.Len())
	}
}

func TestRedisQueue_Ack(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	task := &Task{
		ID:        "task-ack",
		Type:      TaskIssue,
		Domain:    "ack.com",
		Priority:  0,
		CreatedAt: time.Now().Unix(),
	}

	_ = rq.Enqueue(task)
	got, _ := rq.DequeueWithTimeout(1)
	if got == nil {
		t.Fatal("dequeue returned nil")
	}

	// Ack
	if err := rq.Ack(got.ID); err != nil {
		t.Fatalf("Ack failed: %v", err)
	}

	// After Ack, Len should be 0
	if rq.Len() != 0 {
		t.Fatalf("expected Len=0 after Ack, got %d", rq.Len())
	}

	// Double Ack should fail
	if err := rq.Ack(got.ID); err == nil {
		t.Fatal("expected error on double Ack")
	}
}

func TestRedisQueue_Nack(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "sync")
	defer rq.Close()

	task := &Task{
		ID:        "task-nack",
		Type:      TaskSync,
		Domain:    "nack.com",
		Priority:  5, // high priority
		CreatedAt: time.Now().Unix(),
	}

	_ = rq.Enqueue(task)
	got, _ := rq.DequeueWithTimeout(1)
	if got == nil {
		t.Fatal("dequeue returned nil")
	}
	if got.Priority != 5 {
		t.Fatalf("expected priority 5, got %d", got.Priority)
	}

	// Nack
	if err := rq.Nack(got.ID); err != nil {
		t.Fatalf("Nack failed: %v", err)
	}

	// After Nack, task should be back in queue (Len=1, not in processing)
	if rq.Len() != 1 {
		t.Fatalf("expected Len=1 after Nack, got %d", rq.Len())
	}

	// Dequeue again - priority should be 0 after Nack
	got2, _ := rq.DequeueWithTimeout(1)
	if got2 == nil {
		t.Fatal("dequeue after Nack returned nil")
	}
	if got2.Priority != 0 {
		t.Fatalf("expected priority=0 after Nack, got %d", got2.Priority)
	}
	if got2.ID != "task-nack" {
		t.Fatalf("expected same task ID, got '%s'", got2.ID)
	}
}

func TestRedisQueue_Priority(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	// Enqueue normal task first
	normal := &Task{
		ID:        "normal-1",
		Type:      TaskIssue,
		Domain:    "normal.com",
		Priority:  0,
		CreatedAt: time.Now().Unix(),
	}
	_ = rq.Enqueue(normal)

	// Enqueue high priority task second
	high := &Task{
		ID:        "high-1",
		Type:      TaskIssue,
		Domain:    "high.com",
		Priority:  10,
		CreatedAt: time.Now().Unix(),
	}
	_ = rq.Enqueue(high)

	// High priority should be dequeued first (BRPOP checks highKey first)
	got, _ := rq.DequeueWithTimeout(1)
	if got == nil {
		t.Fatal("dequeue returned nil")
	}
	if got.ID != "high-1" {
		t.Fatalf("expected high priority task first, got '%s'", got.ID)
	}
	_ = rq.Ack(got.ID)

	// Then normal
	got2, _ := rq.DequeueWithTimeout(1)
	if got2 == nil {
		t.Fatal("second dequeue returned nil")
	}
	if got2.ID != "normal-1" {
		t.Fatalf("expected normal task second, got '%s'", got2.ID)
	}
	_ = rq.Ack(got2.ID)
}

func TestRedisQueue_DequeueTimeout(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	// Empty queue should timeout
	start := time.Now()
	got, err := rq.DequeueWithTimeout(1)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil on timeout")
	}
	if elapsed < 900*time.Millisecond {
		t.Fatalf("timeout too fast: %v", elapsed)
	}
}

func TestRedisQueue_Close(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")

	_ = rq.Close()

	// Enqueue after close should fail
	task := &Task{ID: "closed-1", Type: TaskIssue, Domain: "closed.com"}
	if err := rq.Enqueue(task); err == nil {
		t.Fatal("expected error on Enqueue after Close")
	}

	// Double close should not panic
	_ = rq.Close()
}

func TestRedisQueue_EnqueueValidation(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	// Nil task
	if err := rq.Enqueue(nil); err == nil {
		t.Fatal("expected error for nil task")
	}

	// Empty ID
	if err := rq.Enqueue(&Task{ID: "", Domain: "x.com"}); err == nil {
		t.Fatal("expected error for empty task ID")
	}
}

func TestRedisQueue_RecoverProcessing(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	// Simulate tasks stuck in processing (as if a previous process crashed)
	task1 := &Task{
		ID:        "stuck-1",
		Type:      TaskIssue,
		Domain:    "stuck1.com",
		Priority:  0,
		CreatedAt: time.Now().Unix(),
	}
	task2 := &Task{
		ID:        "stuck-2",
		Type:      TaskIssue,
		Domain:    "stuck2.com",
		Priority:  3,
		CreatedAt: time.Now().Unix(),
	}

	// Enqueue and dequeue to put them in processing
	_ = rq.Enqueue(task1)
	_ = rq.Enqueue(task2)
	_, _ = rq.DequeueWithTimeout(1)
	_, _ = rq.DequeueWithTimeout(1)

	// Verify both in processing
	if rq.Len() != 2 {
		t.Fatalf("expected Len=2 (both in processing), got %d", rq.Len())
	}

	// RecoverProcessing should move them back to normal queue
	if err := rq.RecoverProcessing(); err != nil {
		t.Fatalf("RecoverProcessing failed: %v", err)
	}

	// Both should be back in queue
	if rq.Len() != 2 {
		t.Fatalf("expected Len=2 after recovery, got %d", rq.Len())
	}

	// Dequeue and verify they're available
	got1, _ := rq.DequeueWithTimeout(1)
	if got1 == nil {
		t.Fatal("first recovered task is nil")
	}
	got2, _ := rq.DequeueWithTimeout(1)
	if got2 == nil {
		t.Fatal("second recovered task is nil")
	}

	// Verify we got both domains
	domains := map[string]bool{got1.Domain: true, got2.Domain: true}
	if !domains["stuck1.com"] || !domains["stuck2.com"] {
		t.Fatalf("unexpected domains after recovery: %v, %v", got1.Domain, got2.Domain)
	}
}

func TestRedisQueue_Len(t *testing.T) {
	rq, _ := setupTestRedisQueue(t, "issue")
	defer rq.Close()

	// Empty
	if rq.Len() != 0 {
		t.Fatalf("expected Len=0, got %d", rq.Len())
	}

	// Add normal
	_ = rq.Enqueue(&Task{ID: "1", Type: TaskIssue, Domain: "a.com", Priority: 0, CreatedAt: 1})
	if rq.Len() != 1 {
		t.Fatalf("expected Len=1, got %d", rq.Len())
	}

	// Add high priority
	_ = rq.Enqueue(&Task{ID: "2", Type: TaskIssue, Domain: "b.com", Priority: 5, CreatedAt: 2})
	if rq.Len() != 2 {
		t.Fatalf("expected Len=2, got %d", rq.Len())
	}

	// Dequeue one (moves to processing)
	_, _ = rq.DequeueWithTimeout(1)
	if rq.Len() != 2 {
		t.Fatalf("expected Len=2 (1 in queue + 1 in processing), got %d", rq.Len())
	}

	// Ack
	_ = rq.Ack("2") // high priority was dequeued first
	if rq.Len() != 1 {
		t.Fatalf("expected Len=1 after Ack, got %d", rq.Len())
	}
}
