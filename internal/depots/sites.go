// Package depots lists the depot sites a gateway can be installed at. The
// three-letter site code appears in device IDs, topics and shipping labels.
package depots

import "time"

// Site codes, as printed on dock signage and in the dispatch system.
const (
	SaltLakeCity = "SLC"
	Reno         = "RNO"
	Boise        = "BOI"
	Denver       = "DEN"
	Phoenix      = "PHX"
)

// Site is one depot.
type Site struct {
	Code     string
	City     string
	TimeZone string
	Docks    int
}

var sites = map[string]Site{
	SaltLakeCity: {Code: SaltLakeCity, City: "Salt Lake City", TimeZone: "America/Denver", Docks: 48},
	Reno:         {Code: Reno, City: "Reno", TimeZone: "America/Los_Angeles", Docks: 32},
	Boise:        {Code: Boise, City: "Boise", TimeZone: "America/Boise", Docks: 18},
	Denver:       {Code: Denver, City: "Denver", TimeZone: "America/Denver", Docks: 40},
	Phoenix:      {Code: Phoenix, City: "Phoenix", TimeZone: "America/Phoenix", Docks: 36},
}

// Lookup returns the site for a code.
func Lookup(code string) (Site, bool) {
	s, ok := sites[code]
	return s, ok
}

// Location returns the site's time zone, falling back to UTC when the zone
// database is missing from the image.
func (s Site) Location() *time.Location {
	loc, err := time.LoadLocation(s.TimeZone)
	if err != nil {
		return time.UTC
	}
	return loc
}
