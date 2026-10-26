package selfupdate

// defaultKeys: oeffentliche Schluessel fuer signierte Manifeste (base64, durch Komma getrennt). Der private Schluessel
// liegt nur bei Dennis und als GitHub-Secret NODE64_SIGNING_KEY; erzeugt mit `go run ./cmd/node64-release keygen`.
const defaultKeys = "CKADRKNeeSdwpqmdt9saWJw1i92EQJdsxmQOs6m/iAw=" // 2026-10-26
