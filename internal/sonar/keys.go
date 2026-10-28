package sonar

// PlanKeys sind die Public Keys (Ed25519, Base64 std), mit denen ipv64.net Messplaene signiert. Ein Plan mit einer
// anderen Signatur wird verworfen. Leer, bis der Schluessel bei ipv64 erzeugt ist (bots/sonar_keygen.php); bis dahin
// nimmt der Kern den Schluessel aus SONAR64_PLAN_KEY (nur Test/Entwicklung, mit Warnung im Log).
var PlanKeys = []string{}
