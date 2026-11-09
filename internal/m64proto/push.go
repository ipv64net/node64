package m64proto

// Push-Betrieb (Agent baut die Verbindung zur Node auf; m64agent/push.go und monitor64/transport/push.go):
//
//	Agent -> Node  "M64PUSH1 <token> <fingerabdruck>\n"  (Kennung, hoechstens PushHelloMax Byte)
//	Node  -> Agent PushAck                               (Token bekannt, Verbindung wartet bei der Node)
//	Node  -> Agent PushStart                             (Node braucht die Verbindung: SSH beginnt)
const (
	DefaultPushPort      = 6466       // Standard-Port des Lauschers der Node (TCP)
	PushMagic            = "M64PUSH1" // Kennung, Version 1
	PushHelloMax         = 160        // Kennung samt Zeilenende hoechstens so lang
	PushAck         byte = 'W'
	PushStart       byte = 'S'
)

// ValidPushToken prueft einen Token: 16 bis 64 Zeichen aus a-z und 0-9.
func ValidPushToken(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
