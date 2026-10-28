package sonar

// PlanKeys sind die Public Keys (Ed25519, Base64 std), mit denen ipv64.net Messplaene signiert. Ein Plan mit einer
// anderen Signatur wird verworfen. Erzeugt bei ipv64 mit bots/sonar_keygen.php (2026-10-28); bei einem Wechsel den
// neuen Schluessel vorne eintragen und den alten erst entfernen, wenn alle Knoten aktualisiert sind.
var PlanKeys = []string{
	"lET4ZrNaug+TvHDnrC80rEzqf4Tlqa1Y2K8jHYOJ0C4=", // kid lET4ZrNa
}
