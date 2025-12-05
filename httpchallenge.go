package main

import (
	"fmt"
	"sync"
)

type HTTPChallengeStore struct {
	mu    sync.RWMutex
	items map[string]string
}

func NewHTTPChallengeStore() *HTTPChallengeStore {
	return &HTTPChallengeStore{
		items: make(map[string]string),
	}
}

func (s *HTTPChallengeStore) Set(token, keyAuth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[token] = keyAuth
}

func (s *HTTPChallengeStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, token)
}

func (s *HTTPChallengeStore) Get(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.items[token]
	return val, ok
}

type HTTPChallengeProvider struct {
	store *HTTPChallengeStore
}

func (p *HTTPChallengeProvider) Present(domain, token, keyAuth string) error {
	if token == "" || keyAuth == "" {
		return fmt.Errorf("token 或 keyAuth 为空")
	}
	p.store.Set(token, keyAuth)
	return nil
}

func (p *HTTPChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	if token == "" {
		return nil
	}
	p.store.Delete(token)
	return nil
}
