package m64agent

import (
	"testing"
	"time"
)

// Stand fuer die Anzeige am Host: Startzeit, letzte Abfrage und die von der Node genannte Version.
func TestServerStatus(t *testing.T) {
	s := &Server{cfg: Config{Version: "0.3.0"}}
	s.status.started = time.Unix(1000, 0)
	if st := s.Status(); st.Version != "0.3.0" || st.Started != 1000 || st.LastRequest != 0 || st.Latest != "" {
		t.Fatalf("fresh: %+v", st)
	}
	s.noteRequest()
	s.SetLatest("0.4.0", time.Unix(2000, 0))
	st := s.Status()
	if st.LastRequest == 0 || st.Latest != "0.4.0" || st.LatestAt != 2000 {
		t.Fatalf("after request: %+v", st)
	}
	for _, bad := range []string{"", "1.0 x", "../x", "a;b", "0.4.0\n"} {
		s.SetLatest(bad, time.Unix(3000, 0))
	}
	if st := s.Status(); st.Latest != "0.4.0" || st.LatestAt != 2000 {
		t.Fatalf("invalid version accepted: %+v", st)
	}
}
