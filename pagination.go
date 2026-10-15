package secureaccess

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/tidwall/gjson"
)

// Paginator performs a GET request and returns all items, merged from all
// pages, as a single plain JSON array. A response that is not paginated still
// yields its items as an array, and an empty collection yields []. A Paginator
// returns an error when it cannot find the items in the response.
type Paginator func(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error)

// pathPaginators maps API path prefixes to the Paginator used for them. The
// longest matching prefix wins. The empty prefix matches every path and sets
// the default.
var pathPaginators = map[string]Paginator{
	"/policies/v2/":                 OffsetLimitListPagination,
	"/policies/v2/objects/":         OffsetLimitKeyedPagination,
	"/policies/v2/destinationlists": PageLimitKeyedPagination,
	"":                              OffsetLimitKeyedPagination,
}

// pathPaginator returns the Paginator registered for the longest prefix of
// path in pathPaginators.
func pathPaginator(path string) Paginator {
	var paginate Paginator
	matched := -1
	for prefix, p := range pathPaginators {
		if strings.HasPrefix(path, prefix) && len(prefix) > matched {
			paginate, matched = p, len(prefix)
		}
	}
	return paginate
}

// itemKeys lists the top-level fields that may carry the items in keyed
// paginator responses, in detection order.
var itemKeys = []string{"results", "data"}

// itemsKey returns the first of itemKeys holding an array in res, or "" if
// none does.
func itemsKey(res Res) string {
	for _, k := range itemKeys {
		if res.Get(k).IsArray() {
			return k
		}
	}
	return ""
}

// OffsetLimitKeyedPagination is a Paginator for responses carrying top-level
// "count" and "limit" fields and the items in a top-level array, whose name is
// detected on the first page from itemKeys. It requests pages
// of maxItems items with the offset and limit query parameters, and merges
// their items into a single plain array. A response without "count" or "limit"
// is not paginated: it is returned as is when it is a plain array, otherwise
// its detected items array is returned. When no items array is found, an
// error is returned.
func OffsetLimitKeyedPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request
	const maxItems = 100

	// Generate Request ID for tracking all get requests under a single ID
	reqID := generateRequestID(8)
	mods = append(mods, RequestID(reqID))

	// Build the merged response in a single pass
	var sb strings.Builder
	sb.WriteByte('[')
	first := true
	offset := 0
	var count, limit int64
	var key string
	for {
		// Get URL path with offset and limit set
		urlPath := pathWithOffset(path, offset, maxItems)

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}

		// The first page tells where the items are and whether the response
		// is paginated
		if offset == 0 {
			// Detect the field carrying the items
			key = itemsKey(raw)

			countRes := raw.Get("count")
			limitRes := raw.Get("limit")

			// Pagination data not available, the response holds all items
			if !countRes.Exists() || !limitRes.Exists() {
				if raw.IsArray() {
					return raw, nil
				}
				if key != "" {
					return raw.Get(key), nil
				}
				return raw, fmt.Errorf("response is not an array and has no items array in any of %q fields", itemKeys)
			}

			if key == "" {
				return raw, fmt.Errorf("no items array found in any of %q fields", itemKeys)
			}

			count, limit = countRes.Int(), limitRes.Int()
		}

		items := raw.Get(key)
		if !items.IsArray() {
			return raw, fmt.Errorf("unexpected non-array %q field (type %s) at offset %d", key, items.Type, offset)
		}

		if offset == 0 {
			// All items are already returned in a single response
			if count <= limit {
				return items, nil
			}
			log.Printf("[DEBUG] [ReqID: %s] Paginated response detected", reqID)
		}

		// Strip surrounding square brackets and append items directly.
		if chunk := strings.TrimSpace(items.Raw[1 : len(items.Raw)-1]); chunk != "" {
			if !first {
				sb.WriteByte(',')
			}
			sb.WriteString(chunk)
			first = false
		}

		// If there are no more pages, stop reading
		if count <= int64(offset+maxItems) {
			break
		}

		// Increase offset to get next bulk of data
		offset += maxItems
	}

	sb.WriteByte(']')
	return gjson.Parse(sb.String()), nil
}

// OffsetLimitListPagination is a Paginator for responses that are a plain JSON
// array of items, without any paging metadata. It requests pages of maxItems
// items with the offset and limit query parameters until a page returns fewer
// than maxItems items, and merges them into a single array. A non-array
// response returns an error.
func OffsetLimitListPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request
	const maxItems = 1000

	// Generate Request ID for tracking all get requests under a single ID
	reqID := generateRequestID(8)
	mods = append(mods, RequestID(reqID))

	// Build the merged response in a single pass
	var sb strings.Builder
	sb.WriteByte('[')
	first := true
	offset := 0
	for {
		// Get URL path with offset and limit set
		urlPath := pathWithOffset(path, offset, maxItems)

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}

		if !raw.IsArray() {
			return raw, fmt.Errorf("unexpected non-array response (type %s) at offset %d", raw.Type, offset)
		}

		items := 0
		raw.ForEach(func(_, _ gjson.Result) bool {
			items++
			return true
		})

		// Strip surrounding square brackets and append items directly.
		if items > 0 {
			if !first {
				sb.WriteByte(',')
			}
			sb.WriteString(strings.TrimSpace(raw.Raw[1 : len(raw.Raw)-1]))
			first = false
		}

		// A short or empty page is the last one
		if items < maxItems {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page at offset %d, requesting next page", reqID, offset)

		// Increase offset to get next bulk of data
		offset += maxItems
	}

	sb.WriteByte(']')
	return gjson.Parse(sb.String()), nil
}

// PageLimitKeyedPagination is a Paginator for responses carrying the items in a
// top-level array, whose name is detected on the first page from itemKeys,
// and optionally the total number of items in "meta.total". It requests pages
// of maxItems items with the page and limit query parameters, starting at page
// 1, until a page returns fewer than maxItems items or the total is reached,
// and merges their items into a single plain array. When no items array is
// found, an error is returned.
func PageLimitKeyedPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request (max is 100)
	const maxItems = 100

	// Generate Request ID for tracking all get requests under a single ID
	reqID := generateRequestID(8)
	mods = append(mods, RequestID(reqID))

	// Build the merged response in a single pass
	var sb strings.Builder
	sb.WriteByte('[')
	first := true
	var key string
	var collected int64
	for page := 1; ; page++ {
		// Get URL path with page and limit set
		urlPath := pathWithPage(path, page, maxItems)

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}

		// Detect the field carrying the items on the first page
		if page == 1 {
			key = itemsKey(raw)
			if key == "" {
				return raw, fmt.Errorf("no items array found in any of %q fields", itemKeys)
			}
		}

		items := raw.Get(key)
		if !items.IsArray() {
			return raw, fmt.Errorf("unexpected non-array %q field (type %s) on page %d", key, items.Type, page)
		}

		n := 0
		items.ForEach(func(_, _ gjson.Result) bool {
			n++
			return true
		})

		// Strip surrounding square brackets and append items directly.
		if n > 0 {
			if !first {
				sb.WriteByte(',')
			}
			sb.WriteString(strings.TrimSpace(items.Raw[1 : len(items.Raw)-1]))
			first = false
		}
		collected += int64(n)

		// A short or empty page, or reaching the total, ends the collection
		total := raw.Get("meta.total")
		if n < maxItems || (total.Exists() && collected >= total.Int()) {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page %d, requesting next page", reqID, page)
	}

	sb.WriteByte(']')
	return gjson.Parse(sb.String()), nil
}
