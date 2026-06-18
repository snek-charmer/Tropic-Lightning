// Package httpsource is a live data-source connector for arbitrary HTTP/JSON
// APIs. An admin configures a URL, an optional dot-path to the array of records,
// and optional auth; a background poller (and a manual refresh) fetches the
// records when the edge node has connectivity and writes them into a generic
// peat dataset, so operators see the last-synced snapshot while disconnected.
package httpsource

import "strings"

// Auth types.
const (
	AuthNone   = "none"
	AuthHeader = "header" // a custom header, e.g. X-API-Key: <value>
	AuthBearer = "bearer" // Authorization: Bearer <value>
)

// Connector is a configured HTTP/JSON source backed by a peat dataset.
type Connector struct {
	Key        string `json:"key"`        // == Collection
	Name       string `json:"name"`       // display name
	Collection string `json:"collection"` // generic dataset collection
	URL        string `json:"url"`
	RecordPath string `json:"record_path"` // dot-path to the records array ("" = response is the array)
	AuthType   string `json:"auth_type"`   // none | header | bearer
	HeaderName string `json:"header_name"` // for AuthHeader (e.g. "X-API-Key")
	AuthValue  string `json:"auth_value"`  // header value or bearer token (stored in the mesh)
}

// AuthTypes lists the selectable auth modes (for the UI).
func AuthTypes() []string { return []string{AuthNone, AuthHeader, AuthBearer} }

// slug normalises a name into a safe collection suffix.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "api"
	}
	return out
}
