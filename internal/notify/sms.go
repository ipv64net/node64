package notify

import (
	"errors"
	"strings"
)

// SMSNumber bringt eine Mobilnummer in das Format des ipv64-SMS-Gateways (Laendervorwahl mit 00,
// z. B. 00491771234567). Erlaubt: "+49 177 1234567", "0049 177 1234567", "49 177 1234567".
// Nationale Schreibweise ("0177 ...") wird abgelehnt: das Land ist daraus nicht erkennbar.
func SMSNumber(in string) (string, error) {
	var b strings.Builder
	for i, r := range strings.TrimSpace(in) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteString("00")
		}
	}
	n := b.String()
	switch {
	case n == "":
		return "", errors.New("number is required")
	case strings.HasPrefix(n, "00"):
	case strings.HasPrefix(n, "0"):
		return "", errors.New("number needs the country code, e.g. +49 177 1234567")
	default:
		n = "00" + n
	}
	if len(n) < 9 || len(n) > 22 {
		return "", errors.New("number has an invalid length")
	}
	return n, nil
}
