package utils

import (
	"fmt"
	"sync"
	"time"
)

// TokenBucket implements token bucket algorithm for rate limiting
type TokenBucket struct {
	capacity   int
	tokens     int
	refillRate int // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, refillRate int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if request is allowed and consumes a token
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// TokensRemaining returns number of tokens remaining
func (tb *TokenBucket) TokensRemaining() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int(elapsed.Seconds()) * tb.refillRate

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// SlidingWindowRateLimiter implements sliding window rate limiting
type SlidingWindowRateLimiter struct {
	window   time.Duration
	limit    int
	requests map[string][]time.Time
	mu       sync.RWMutex
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter
func NewSlidingWindowRateLimiter(window time.Duration, limit int) *SlidingWindowRateLimiter {
	limiter := &SlidingWindowRateLimiter{
		window:   window,
		limit:    limit,
		requests: make(map[string][]time.Time),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow checks if request is allowed for the given key
func (sw *SlidingWindowRateLimiter) Allow(key string) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-sw.window)

	// Get requests for this key
	requests, exists := sw.requests[key]
	if !exists {
		requests = make([]time.Time, 0)
	}

	// Remove old requests outside the window
	validRequests := make([]time.Time, 0)
	for _, reqTime := range requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if we can add a new request
	if len(validRequests) >= sw.limit {
		sw.requests[key] = validRequests
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	sw.requests[key] = validRequests

	return true
}

// RemainingRequests returns number of remaining requests for the key
func (sw *SlidingWindowRateLimiter) RemainingRequests(key string) int {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-sw.window)

	requests, exists := sw.requests[key]
	if !exists {
		return sw.limit
	}

	// Count valid requests
	validCount := 0
	for _, reqTime := range requests {
		if reqTime.After(windowStart) {
			validCount++
		}
	}

	remaining := sw.limit - validCount
	if remaining < 0 {
		remaining = 0
	}

	return remaining
}

// cleanup removes old entries periodically
func (sw *SlidingWindowRateLimiter) cleanup() {
	ticker := time.NewTicker(sw.window)
	defer ticker.Stop()

	for range ticker.C {
		sw.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-sw.window)

		for key, requests := range sw.requests {
			validRequests := make([]time.Time, 0)
			for _, reqTime := range requests {
				if reqTime.After(windowStart) {
					validRequests = append(validRequests, reqTime)
				}
			}

			if len(validRequests) == 0 {
				delete(sw.requests, key)
			} else {
				sw.requests[key] = validRequests
			}
		}
		sw.mu.Unlock()
	}
}

// RateLimitInfo contains rate limit information
type RateLimitInfo struct {
	Limit      int
	Remaining  int
	Reset      time.Time
	RetryAfter *time.Duration
}

// ToHeaders converts rate limit info to HTTP headers
func (r *RateLimitInfo) ToHeaders() map[string]string {
	headers := map[string]string{
		"X-RateLimit-Limit":     fmt.Sprintf("%d", r.Limit),
		"X-RateLimit-Remaining": fmt.Sprintf("%d", r.Remaining),
		"X-RateLimit-Reset":     fmt.Sprintf("%d", r.Reset.Unix()),
	}

	if r.RetryAfter != nil {
		headers["Retry-After"] = fmt.Sprintf("%.0f", r.RetryAfter.Seconds())
	}

	return headers
}

// FixedWindowRateLimiter implements fixed window rate limiting
type FixedWindowRateLimiter struct {
	window   time.Duration
	limit    int
	counters map[string]*windowCounter
	mu       sync.RWMutex
}

type windowCounter struct {
	count       int
	windowStart time.Time
	mu          sync.Mutex
}

// NewFixedWindowRateLimiter creates a new fixed window rate limiter
func NewFixedWindowRateLimiter(window time.Duration, limit int) *FixedWindowRateLimiter {
	limiter := &FixedWindowRateLimiter{
		window:   window,
		limit:    limit,
		counters: make(map[string]*windowCounter),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow checks if request is allowed for the given key
func (fw *FixedWindowRateLimiter) Allow(key string) (bool, RateLimitInfo) {
	fw.mu.Lock()
	counter, exists := fw.counters[key]
	if !exists {
		counter = &windowCounter{
			count:       0,
			windowStart: time.Now(),
		}
		fw.counters[key] = counter
	}
	fw.mu.Unlock()

	counter.mu.Lock()
	defer counter.mu.Unlock()

	now := time.Now()

	// Check if we need to reset the window
	if now.Sub(counter.windowStart) >= fw.window {
		counter.count = 0
		counter.windowStart = now
	}

	info := RateLimitInfo{
		Limit:     fw.limit,
		Remaining: fw.limit - counter.count,
		Reset:     counter.windowStart.Add(fw.window),
	}

	if counter.count >= fw.limit {
		retryAfter := counter.windowStart.Add(fw.window).Sub(now)
		info.RetryAfter = &retryAfter
		return false, info
	}

	counter.count++
	info.Remaining = fw.limit - counter.count

	return true, info
}

// cleanup removes old counters periodically
func (fw *FixedWindowRateLimiter) cleanup() {
	ticker := time.NewTicker(fw.window * 2)
	defer ticker.Stop()

	for range ticker.C {
		fw.mu.Lock()
		now := time.Now()

		for key, counter := range fw.counters {
			counter.mu.Lock()
			if now.Sub(counter.windowStart) > fw.window*2 {
				delete(fw.counters, key)
			}
			counter.mu.Unlock()
		}
		fw.mu.Unlock()
	}
}
