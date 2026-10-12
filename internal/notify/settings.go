package notify

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SyncedSettings sind die Benachrichtigungs-Einstellungen, die fuer den ganzen Account gelten:
// Nodes und ipv64 gleichen sie ab, damit Ruhezeiten und Grenzen ueberall dieselben sind.
var SyncedSettings = []string{SetQuietEnabled, SetQuietFrom, SetQuietTo, SetQuietDays, SetQuietTZ, SetRatePerHour, SetBatchThreshold, SetBatchWindow}

// Grenzen der Zahlenwerte (Node, hub und Portal gleich).
var settingRanges = map[string][2]int{SetRatePerHour: {0, 1000}, SetBatchThreshold: {0, 100}, SetBatchWindow: {0, 600}}

// NormalizeSetting prueft einen Einstellungswert und bringt ihn in die gespeicherte Form.
func NormalizeSetting(key, v string) (string, error) {
	v = strings.TrimSpace(v)
	switch key {
	case SetQuietEnabled:
		switch strings.ToLower(v) {
		case "1", "true", "on", "yes":
			return "1", nil
		case "", "0", "false", "off", "no":
			return "0", nil
		}
		return "", errors.New(key + " must be 0 or 1")
	case SetQuietFrom, SetQuietTo:
		t, err := time.Parse("15:04", v)
		if err != nil {
			return "", errors.New(key + " must be a time like 22:00")
		}
		return t.Format("15:04"), nil
	case SetQuietDays:
		seen := map[int]bool{}
		var days []int
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 7 {
				return "", errors.New(key + " must list weekdays 1 (Monday) to 7 (Sunday)")
			}
			if !seen[n] {
				seen[n] = true
				days = append(days, n)
			}
		}
		sort.Ints(days)
		out := make([]string, len(days))
		for i, n := range days {
			out[i] = strconv.Itoa(n)
		}
		return strings.Join(out, ","), nil // leer = an keinem Tag
	case SetQuietTZ:
		if v == "" {
			return "", nil
		}
		if _, err := time.LoadLocation(v); err != nil {
			return "", errors.New(key + " must be a time zone like Europe/Berlin")
		}
		return v, nil
	}
	if r, ok := settingRanges[key]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < r[0] || n > r[1] {
			return "", errors.New(key + " must be a number from " + strconv.Itoa(r[0]) + " to " + strconv.Itoa(r[1]))
		}
		return strconv.Itoa(n), nil
	}
	return v, nil
}

// IsSyncedSetting meldet, ob der Schluessel account-weit abgeglichen wird.
func IsSyncedSetting(key string) bool {
	for _, k := range SyncedSettings {
		if k == key {
			return true
		}
	}
	return false
}
