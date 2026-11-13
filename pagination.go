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
// returns an error when it cannot find the items in the response. The
// returned Res carries the HTTP status code and request ID of the last page
// requested. All pages share the request ID set by Client.GetAllWithPaginator.
type Paginator func(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error)

// pathPaginators maps API path prefixes to the Paginator used for them. The
// longest matching prefix wins. The empty prefix matches every path and sets
// the default.
var pathPaginators = map[string]Paginator{
	"/policies/v2/":                                      OffsetLimitListPagination,
	"/policies/v2/objects/":                              OffsetLimitKeyedPagination,
	"/policies/v2/privateResourceGroups":                 OffsetLimitKeyedPagination,
	"/policies/v2/doNotDecryptLists":                     PageLimitListPagination,
	"/policies/v2/destinationlists":                      PageLimitKeyedPagination,
	"/policies/v2/applicationCategories":                 PageLimitMapPagination,
	"/policies/v2/applicationCategories?optionalFields=": PageLimitListPagination,
	"/policies/v2/landerSettings":                        ListNoPagination,
	"/policies/v2/enterpriseApplications":                ListNoPagination,
	"/policies/v2/threatCategories":                      ListNoPagination,
	"/policies/v2/dlp/custom/dataIdentifiers":            OffsetLikePageLimitListPagination,
	"/policies/v2/dlp/builtIn/dataIdentifiers":           OffsetLikePageLimitListPagination,
	"/policies/v2/dlp/builtIn/classifications":           ListNoPagination,
	"/policies/v2/dlp/custom/classifications":            ListNoPagination,
	"/deployments/v2/sites":                              PageLimitListPagination,
	"/deployments/v2/networks":                           PageLimitListPagination,
	"/reports/v2/categories":                             KeyedNoPagination,
	"":                                                   OffsetLimitKeyedPagination,
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
var itemKeys = []string{"results", "data", "items"}

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

// arrayMerger merges items from several pages into a single JSON array. The
// zero value is an empty merger ready to use.
type arrayMerger struct {
	sb strings.Builder
	n  int
}

// add appends a single item.
func (m *arrayMerger) add(item gjson.Result) {
	if m.n > 0 {
		m.sb.WriteByte(',')
	}
	m.sb.WriteString(item.Raw)
	m.n++
}

// addAll appends the elements of a JSON array, or the values of a JSON object
// in response order, and returns how many were appended.
func (m *arrayMerger) addAll(r gjson.Result) int {
	n := 0
	r.ForEach(func(_, item gjson.Result) bool {
		m.add(item)
		n++
		return true
	})
	return n
}

// result returns the merged items as a JSON array, with the HTTP status code
// and request ID of last, the last page response.
func (m *arrayMerger) result(last Res) Res {
	return Res{
		Result:     gjson.Parse("[" + m.sb.String() + "]"),
		StatusCode: last.StatusCode,
		RequestID:  last.RequestID,
	}
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

	var merged arrayMerger
	var last Res
	offset := 0
	var count, limit int64
	var key string
	for {
		// Get URL path with offset and limit set
		urlPath, err := pathWithOffset(path, offset, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

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
					return Res{Result: raw.Get(key), StatusCode: raw.StatusCode, RequestID: raw.RequestID}, nil
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
				return Res{Result: items, StatusCode: raw.StatusCode, RequestID: raw.RequestID}, nil
			}
			log.Printf("[DEBUG] [ReqID: %s] Paginated response detected", raw.RequestID)
		}

		merged.addAll(items)

		// If there are no more pages, stop reading
		if count <= int64(offset+maxItems) {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Non-empty page at offset %d, requesting next page", raw.RequestID, offset)

		// Increase offset to get next bulk of data
		offset += maxItems
	}

	return merged.result(last), nil
}

// OffsetLimitListPagination is a Paginator for responses that are a plain JSON
// array of items, without any paging metadata. It requests pages of maxItems
// items with the offset and limit query parameters until a page returns fewer
// than maxItems items, and merges them into a single array. A non-array
// response returns an error.
func OffsetLimitListPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request
	const maxItems = 1000

	var merged arrayMerger
	var last Res
	offset := 0
	for {
		// Get URL path with offset and limit set
		urlPath, err := pathWithOffset(path, offset, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

		if !raw.IsArray() {
			return raw, fmt.Errorf("unexpected non-array response (type %s) at offset %d", raw.Type, offset)
		}

		// A short or empty page is the last one
		if merged.addAll(raw.Result) < maxItems {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page at offset %d, requesting next page", raw.RequestID, offset)

		// Increase offset to get next bulk of data
		offset += maxItems
	}

	return merged.result(last), nil
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

	var merged arrayMerger
	var last Res
	var key string
	var collected int64
	for page := 1; ; page++ {
		// Get URL path with page and limit set
		urlPath, err := pathWithPage(path, page, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

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

		n := merged.addAll(items)
		collected += int64(n)

		// A short or empty page, or reaching the total, ends the collection
		total := raw.Get("meta.total")
		if n < maxItems || (total.Exists() && collected >= total.Int()) {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page %d, requesting next page", raw.RequestID, page)
	}

	return merged.result(last), nil
}

// PageLimitMapPagination is a Paginator for responses that are a JSON object
// mapping item IDs to items, without any paging metadata. It requests pages of
// maxItems items with the page and limit query parameters, starting at page 1,
// until a page returns fewer than maxItems items or an empty object or array,
// and merges the item values, in response order, into a single plain array.
// Any other response returns an error.
func PageLimitMapPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request
	const maxItems = 100

	var merged arrayMerger
	var last Res
	for page := 1; ; page++ {
		// Get URL path with page and limit set
		urlPath, err := pathWithPage(path, page, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

		// An empty list means there are no more items
		if raw.IsArray() && len(raw.Array()) == 0 {
			break
		}

		if !raw.IsObject() {
			return raw, fmt.Errorf("unexpected non-object response (type %s) on page %d", raw.Type, page)
		}

		// Append the map values, dropping their keys. A short or empty page is
		// the last one.
		if merged.addAll(raw.Result) < maxItems {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page %d, requesting next page", raw.RequestID, page)
	}

	return merged.result(last), nil
}

// PageLimitListPagination is a Paginator for responses that are a plain JSON
// array of items, without any paging metadata. It requests pages of maxItems
// items with the page and limit query parameters, starting at page 1, until a
// page returns fewer than maxItems items, and merges them into a single array.
// A non-array response returns an error.
func PageLimitListPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {
	// Maximum number of items retrieved in a single page request
	const maxItems = 100

	var merged arrayMerger
	var last Res
	for page := 1; ; page++ {
		// Get URL path with page and limit set
		urlPath, err := pathWithPage(path, page, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

		if !raw.IsArray() {
			return raw, fmt.Errorf("unexpected non-array response (type %s) on page %d", raw.Type, page)
		}

		// A short or empty page is the last one
		if merged.addAll(raw.Result) < maxItems {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Full page %d, requesting next page", raw.RequestID, page)
	}

	return merged.result(last), nil
}

// KeyedNoPagination is a Paginator that returns all items in a single request without any paging.
func KeyedNoPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {

	// Execute query
	raw, err := client.get(ctx, path, mods...)
	if err != nil {
		return raw, err
	}
	key := itemsKey(raw)
	if key == "" {
		return raw, fmt.Errorf("[DEBUG] [ReqID: %s] no items array found in any of %q fields", raw.RequestID, itemKeys)
	}
	raw.Result = raw.Result.Get(key)
	return raw, nil
}

// ListNoPagination is a Paginator that returns all items in a single request without any paging.
func ListNoPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {

	// Execute query
	return client.get(ctx, path, mods...)
}

// OffsetLikePageLimitListPagination is a Paginator that behaves like PageLimitListPagination,
// but uses on offset parameter, where in fact this behaves like a page. Pages are
// requested until an empty page is returned.
func OffsetLikePageLimitListPagination(ctx context.Context, client *Client, path string, mods ...func(*Req)) (Res, error) {

	// Maximum number of items retrieved in a single page request
	const maxItems = 100

	var merged arrayMerger
	var last Res
	for offset := 0; ; offset += 1 {
		// Get URL path with offset and limit set
		urlPath, err := pathWithOffset(path, offset, maxItems)
		if err != nil {
			return Res{}, err
		}

		// Execute query
		raw, err := client.get(ctx, urlPath, mods...)
		if err != nil {
			return raw, err
		}
		last = raw

		if !raw.IsArray() {
			return raw, fmt.Errorf("unexpected non-array response (type %s) at offset %d", raw.Type, offset)
		}

		// Only an empty page marks the end
		if merged.addAll(raw.Result) == 0 {
			break
		}

		log.Printf("[DEBUG] [ReqID: %s] Non-empty page at offset %d, requesting next page", raw.RequestID, offset)
	}

	return merged.result(last), nil
}
