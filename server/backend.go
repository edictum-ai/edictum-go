package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Backend implements session.StorageBackend and session.BatchGetter
// by delegating all state to the edictum-server session API.
//
// Fail-closed: network errors always propagate. Only a genuine 404
// returns ("", nil) from Get — any other failure is surfaced so the
// pipeline denies rather than silently allowing with missing data.
type Backend struct {
	client *Client
}

// NewBackend creates a backend backed by the given client.
func NewBackend(client *Client) *Backend {
	return &Backend{client: client}
}

// Get retrieves a value from the server session store.
// Returns ("", nil) when the key does not exist (HTTP 404).
func (b *Backend) Get(ctx context.Context, key string) (string, error) {
	resp, err := b.client.Get(ctx, "/api/v1/sessions/"+url.PathEscape(key))
	if err != nil {
		return "", err
	}
	if resp == nil {
		// 404 — key does not exist.
		return "", nil
	}
	val, ok := resp["value"].(string)
	if !ok {
		return "", fmt.Errorf("server response missing or non-string 'value' field")
	}
	return val, nil
}

// Set stores a value in the server session store.
func (b *Backend) Set(ctx context.Context, key, value string) error {
	_, err := b.client.Put(ctx, "/api/v1/sessions/"+url.PathEscape(key), map[string]string{"value": value})
	return err
}

// Delete removes a key from the server session store.
// Silently succeeds if the key does not exist (404).
func (b *Backend) Delete(ctx context.Context, key string) error {
	_, err := b.client.Delete(ctx, "/api/v1/sessions/"+url.PathEscape(key))
	if err != nil {
		var se *Error
		if errors.As(err, &se) && se.StatusCode == 404 {
			return nil
		}
		return err
	}
	return nil
}

// Increment atomically increments a counter on the server.
func (b *Backend) Increment(ctx context.Context, key string, amount int) (int, error) {
	resp, err := b.client.Post(ctx, "/api/v1/sessions/"+url.PathEscape(key)+"/increment", map[string]int{"amount": amount})
	if err != nil {
		return 0, err
	}
	val, ok := resp["value"]
	if !ok {
		return 0, fmt.Errorf("server response missing 'value' field")
	}
	switch v := val.(type) {
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("unexpected value type %T in increment response", val)
	}
}

// BatchGet retrieves multiple session values in a single HTTP call.
// Falls back to individual Get calls if the server returns 404 or 405
// (endpoint not available on older servers).
func (b *Backend) BatchGet(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}

	resp, err := b.client.Post(ctx, "/api/v1/sessions/batch", map[string][]string{"keys": keys})
	if err != nil {
		var se *Error
		if errors.As(err, &se) && (se.StatusCode == 404 || se.StatusCode == 405) {
			return b.fallbackBatchGet(ctx, keys)
		}
		return nil, err
	}

	values, ok := resp["values"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("server batch response missing or malformed 'values' map")
	}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if v, ok := values[key]; ok {
			if s, ok := v.(string); ok {
				result[key] = s
			}
		}
	}
	return result, nil
}

func (b *Backend) fallbackBatchGet(ctx context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		val, err := b.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}
	return result, nil
}
