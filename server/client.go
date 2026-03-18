package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// ClientConfig holds configuration for the server client.
type ClientConfig struct {
	BaseURL       string
	APIKey        string
	AgentID       string
	Env           string
	BundleName    string
	Tags          map[string]string
	Timeout       time.Duration
	MaxRetries    int
	AllowInsecure bool
}

// Client is an HTTP client for the edictum-server API.
// It handles authentication, retries, and TLS enforcement.
type Client struct {
	baseURL    string
	apiKey     string
	agentID    string
	env        string
	bundleName string
	tags       map[string]string
	maxRetries int
	httpClient *http.Client
}

// NewClient creates a validated Client. Returns an error if configuration
// is invalid (bad identifiers, TLS violation, tag limits).
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.AgentID == "" {
		cfg.AgentID = "default"
	}
	if cfg.Env == "" {
		cfg.Env = "production"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}

	if err := enforceTLS(cfg.BaseURL, cfg.AllowInsecure); err != nil {
		return nil, err
	}
	if err := validateIdentifier("agent_id", cfg.AgentID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("env", cfg.Env); err != nil {
		return nil, err
	}
	if cfg.BundleName != "" {
		if err := validateIdentifier("bundle_name", cfg.BundleName); err != nil {
			return nil, err
		}
	}
	if cfg.Tags != nil {
		if err := validateTags(cfg.Tags); err != nil {
			return nil, err
		}
	}

	// Strip trailing slash from base URL for consistent path joining.
	base := cfg.BaseURL
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}

	return &Client{
		baseURL:    base,
		apiKey:     cfg.APIKey,
		agentID:    cfg.AgentID,
		env:        cfg.Env,
		bundleName: cfg.BundleName,
		tags:       cfg.Tags,
		maxRetries: cfg.MaxRetries,
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// Get sends a GET request. Returns (nil, nil) for 404 responses.
func (c *Client) Get(ctx context.Context, path string) (map[string]any, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil, true)
}

// Post sends a POST request with a JSON body.
func (c *Client) Post(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.doRequest(ctx, http.MethodPost, path, body, false)
}

// Put sends a PUT request with a JSON body.
func (c *Client) Put(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.doRequest(ctx, http.MethodPut, path, body, false)
}

// Delete sends a DELETE request.
func (c *Client) Delete(ctx context.Context, path string) (map[string]any, error) {
	return c.doRequest(ctx, http.MethodDelete, path, nil, false)
}

// AgentID returns the configured agent ID.
func (c *Client) AgentID() string { return c.agentID }

// Env returns the configured environment.
func (c *Client) Env() string { return c.env }

// BundleName returns the configured bundle name.
func (c *Client) BundleName() string { return c.bundleName }

// doRequest executes an HTTP request with exponential backoff retry.
// Only GET requests are retried on network errors and 5xx responses.
// POST/PUT/DELETE are non-idempotent and must not be retried to avoid
// duplicate side effects (e.g., double session increments, duplicate approvals).
// When nilOn404 is true, a 404 response returns (nil, nil).
func (c *Client) doRequest(
	ctx context.Context,
	method, path string,
	body any,
	nilOn404 bool,
) (map[string]any, error) {
	var lastErr error
	idempotent := method == http.MethodGet

	for attempt := range c.maxRetries {
		req, err := c.buildRequest(ctx, method, path, body)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if !idempotent {
				return nil, err
			}
			lastErr = err
			if attempt < c.maxRetries-1 {
				sleepBackoff(ctx, attempt)
				continue
			}
			return nil, lastErr
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			if !idempotent {
				return nil, fmt.Errorf("read response: %w", readErr)
			}
			lastErr = fmt.Errorf("read response: %w", readErr)
			if attempt < c.maxRetries-1 {
				sleepBackoff(ctx, attempt)
				continue
			}
			return nil, lastErr
		}

		if resp.StatusCode >= 500 {
			if !idempotent {
				return nil, &Error{StatusCode: resp.StatusCode, Detail: string(respBody)}
			}
			lastErr = &Error{StatusCode: resp.StatusCode, Detail: string(respBody)}
			if attempt < c.maxRetries-1 {
				sleepBackoff(ctx, attempt)
				continue
			}
			return nil, lastErr
		}

		if resp.StatusCode == 404 && nilOn404 {
			return nil, nil
		}

		if resp.StatusCode >= 400 {
			return nil, &Error{StatusCode: resp.StatusCode, Detail: string(respBody)}
		}

		var result map[string]any
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &result); err != nil {
				return nil, fmt.Errorf("decode response: %w", err)
			}
		}
		return result, nil
	}

	return nil, lastErr
}

func (c *Client) buildRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Edictum-Agent-Id", c.agentID)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// sleepBackoff sleeps for exponential backoff: 0.5s * 2^attempt.
// Respects context cancellation.
func sleepBackoff(ctx context.Context, attempt int) {
	delay := time.Duration(float64(500*time.Millisecond) * math.Pow(2, float64(attempt)))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
