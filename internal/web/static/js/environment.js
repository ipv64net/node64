// Environment: das Ticket bzw. die Anmeldeseite der anderen Node sofort oeffnen (der Knopf bleibt als Rueckfall).
(function () {
	'use strict';
	var f = document.getElementById('env-enter');
	if (f) {
		f.submit();
		return;
	}
	var a = document.getElementById('env-login');
	if (a) {
		window.location.replace(a.href);
	}
})();
