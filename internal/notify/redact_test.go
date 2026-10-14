package notify

import "testing"

func TestRedactURLs(t *testing.T) {
	cases := map[string]string{
		`Post "https://api.telegram.org/bot123:SECRET/sendMessage": dial tcp: timeout`: `Post "https://api.telegram.org/…": dial tcp: timeout`,
		`Post "https://discord.com/api/webhooks/1/tok?wait=true": EOF`:                 `Post "https://discord.com/…": EOF`,
		`status 500 from https://user:pw@hook.example/x`:                               `status 500 from https://hook.example/…`,
		`connection refused`:  `connection refused`,
		`https://example.com`: `https://example.com`,
	}
	for in, want := range cases {
		if got := RedactURLs(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
