// Package weather is a live data-source connector for the Open-Meteo API
// (open-meteo.com). An admin configures one or more locations; a background
// poller fetches current conditions when the edge node has connectivity and
// writes them into a generic peat dataset, so operators see the last-synced
// weather even while disconnected (DDIL).
package weather

import "strings"

// Location is a named point to fetch weather for.
type Location struct {
	Label string  `json:"label"`
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

// Connector is a configured weather source: a set of locations backed by a peat
// dataset collection that the poller refreshes.
type Connector struct {
	Key        string     `json:"key"`        // == Collection
	Name       string     `json:"name"`       // display name
	Collection string     `json:"collection"` // generic dataset collection
	Locations  []Location `json:"locations"`
}

// columns is the fixed schema the connector writes for each location.
var columns = []string{"location", "latitude", "longitude", "temperature_c", "wind_kph", "weather", "observed_at"}

// slug normalises a name into a safe collection suffix (mirrors dataset.slug).
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
		out = "weather"
	}
	return out
}

// wmoText maps a WMO weather-interpretation code to a short description.
// https://open-meteo.com/en/docs#weathervariables
func wmoText(code int) string {
	switch {
	case code == 0:
		return "Clear"
	case code == 1:
		return "Mainly clear"
	case code == 2:
		return "Partly cloudy"
	case code == 3:
		return "Overcast"
	case code == 45 || code == 48:
		return "Fog"
	case code >= 51 && code <= 57:
		return "Drizzle"
	case code >= 61 && code <= 67:
		return "Rain"
	case code >= 71 && code <= 77:
		return "Snow"
	case code >= 80 && code <= 82:
		return "Rain showers"
	case code >= 85 && code <= 86:
		return "Snow showers"
	case code >= 95 && code <= 99:
		return "Thunderstorm"
	default:
		return "Unknown"
	}
}
