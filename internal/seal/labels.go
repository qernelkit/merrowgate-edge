package seal

import (
	"fmt"
	"strings"
	"unicode"
)

// SealedPackageLabel is the text printed on the tamper-evident sticker that closes
// a replacement unit's shipping box. Depot staff compare the number with the
// dispatch note before they break the sticker.
func SealedPackageLabel(id string) string {
	return fmt.Sprintf("MERROWGATE SYSTEMS | REPLACEMENT UNIT %s | CHECK NUMBER BEFORE OPENING", labelID(id))
}

// ReturnLabel is printed for a faulty unit going back to the repair centre.
func ReturnLabel(id, site, reason string) string {
	return fmt.Sprintf("RETURN %s FROM %s: %s", labelID(id), strings.ToUpper(site), strings.ToUpper(reason))
}

// labelID keeps letters, digits and dashes so the label printer's font can show it.
func labelID(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-', unicode.IsDigit(r):
			return r
		case unicode.IsLetter(r) && r < unicode.MaxASCII:
			return unicode.ToUpper(r)
		}
		return -1
	}, id)
}
