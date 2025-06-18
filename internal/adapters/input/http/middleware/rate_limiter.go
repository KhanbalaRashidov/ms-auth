package middleware

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/patrickmn/go-cache"
	"ms-auth/pkg/utils"
	"sync"
	"time"
)

// RateLimiter creates a rate limiting middleware
func RateLimiter(requestsPerMinute int) fiber.Handler {
	// Create in-memory cache for rate limiting
	rateLimitCache := cache.New(time.Minute, 2*time.Minute)
	mu := &sync.RWMutex{}

	return func(c *fiber.Ctx) error {
		// Get client IP
		clientIP := c.IP()

		// Create cache key
		key := "rate_limit:" + clientIP

		mu.Lock()
		defer mu.Unlock()

		// Get current count from cache
		countInterface, found := rateLimitCache.Get(key)
		var count int
		if found {
			count = countInterface.(int)
		}

		// Check if limit exceeded
		if count >= requestsPerMinute {
			return utils.ErrorResponse(c, 429, "Rate limit exceeded", nil)
		}

		// Increment counter
		count++
		rateLimitCache.Set(key, count, time.Minute)

		// Set rate limit headers (convert int to string properly)
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", requestsPerMinute))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", requestsPerMinute-count))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		return c.Next()
	}
}

// LoginRateLimiter creates a specific rate limiter for login attempts
func LoginRateLimiter(maxAttempts int, window time.Duration) fiber.Handler {
	loginCache := cache.New(window, 2*window)
	mu := &sync.RWMutex{}

	return func(c *fiber.Ctx) error {
		// Only apply to login endpoints
		if c.Path() != "/api/v1/auth/login" {
			return c.Next()
		}

		clientIP := c.IP()
		key := "login_attempts:" + clientIP

		mu.RLock()
		countInterface, found := loginCache.Get(key)
		mu.RUnlock()

		var count int
		if found {
			count = countInterface.(int)
		}

		if count >= maxAttempts {
			// Set retry-after header
			c.Set("Retry-After", fmt.Sprintf("%.0f", window.Seconds()))
			return utils.ErrorResponse(c, 429, "Too many login attempts. Please try again later.", nil)
		}

		// Continue to handler first, then increment on actual attempt
		return c.Next()
	}
}

// LoginAttemptTracker tracks actual login attempts (call this in login handler)
func IncrementLoginAttempt(clientIP string, window time.Duration) {
	// This should be called from login handler after actual login attempt
	loginCache := cache.New(window, 2*window)
	mu := &sync.RWMutex{}

	key := "login_attempts:" + clientIP

	mu.Lock()
	defer mu.Unlock()

	countInterface, found := loginCache.Get(key)
	var count int
	if found {
		count = countInterface.(int)
	}

	count++
	loginCache.Set(key, count, window)
}

// RegisterRateLimiter creates a specific rate limiter for registration attempts
func RegisterRateLimiter(maxAttempts int, window time.Duration) fiber.Handler {
	registerCache := cache.New(window, 2*window)
	mu := &sync.RWMutex{}

	return func(c *fiber.Ctx) error {
		// Only apply to register endpoints
		if c.Path() != "/api/v1/auth/register" {
			return c.Next()
		}

		clientIP := c.IP()
		key := "register_attempts:" + clientIP

		mu.RLock()
		countInterface, found := registerCache.Get(key)
		mu.RUnlock()

		var count int
		if found {
			count = countInterface.(int)
		}

		if count >= maxAttempts {
			// Set retry-after header
			c.Set("Retry-After", fmt.Sprintf("%.0f", window.Seconds()))
			return utils.ErrorResponse(c, 429, "Too many registration attempts. Please try again later.", nil)
		}

		// Increment counter after check
		mu.Lock()
		count++
		registerCache.Set(key, count, window)
		mu.Unlock()

		// Set rate limit headers
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxAttempts))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", maxAttempts-count))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))

		return c.Next()
	}
}

// IPBasedRateLimiter creates more sophisticated IP-based rate limiter
func IPBasedRateLimiter(requestsPerMinute int, burstSize int) fiber.Handler {
	type bucket struct {
		tokens     int
		lastRefill time.Time
		mu         sync.Mutex
	}

	buckets := sync.Map{}

	return func(c *fiber.Ctx) error {
		clientIP := c.IP()

		// Get or create bucket for this IP
		bucketInterface, _ := buckets.LoadOrStore(clientIP, &bucket{
			tokens:     burstSize,
			lastRefill: time.Now(),
		})

		b := bucketInterface.(*bucket)

		b.mu.Lock()
		defer b.mu.Unlock()

		// Refill tokens based on time passed
		now := time.Now()
		elapsed := now.Sub(b.lastRefill)
		tokensToAdd := int(elapsed.Seconds() * float64(requestsPerMinute) / 60.0)

		if tokensToAdd > 0 {
			b.tokens += tokensToAdd
			if b.tokens > burstSize {
				b.tokens = burstSize
			}
			b.lastRefill = now
		}

		// Check if request can be served
		if b.tokens <= 0 {
			c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", requestsPerMinute))
			c.Set("X-RateLimit-Remaining", "0")
			c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", now.Add(time.Minute).Unix()))
			c.Set("Retry-After", "60")
			return utils.ErrorResponse(c, 429, "Rate limit exceeded", nil)
		}

		// Consume token
		b.tokens--

		// Set headers
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", requestsPerMinute))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", b.tokens))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", now.Add(time.Minute).Unix()))

		return c.Next()
	}
}
