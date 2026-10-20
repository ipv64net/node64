package honeypot

import (
	"context"
	"log/slog"
)

// Platzhalter (H5 Vertrag): wird vom Teil „Log-Sensor“ ersetzt. Signaturen bleiben.

// LogSensor liest Dateien und Syslog, wendet die Regeln an und meldet Ereignisse an die Sink.
type LogSensor struct {
	log *slog.Logger
}

// NewLogSensor legt den Log-Sensor an (noch nichts geoeffnet).
func NewLogSensor(log *slog.Logger) *LogSensor { return &LogSensor{log: log} }

// Apply startet, aendert oder stoppt Dateien und Syslog-Empfaenger nach cfg. Leere cfg = alles aus.
func (s *LogSensor) Apply(ctx context.Context, cfg LogConfig, sink Sink) LogStatus {
	return LogStatus{Files: []LogFileStatus{}}
}

// Stop beendet alles.
func (s *LogSensor) Stop() {}

// Status liefert den aktuellen Zustand.
func (s *LogSensor) Status() LogStatus { return LogStatus{Files: []LogFileStatus{}} }
