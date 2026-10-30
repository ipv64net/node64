<?php
/**
 * Healthchecks 2.0: gemeinsamer Versand ueber ipv64 (Mail, SMS) fuer die hub-Bruecke (hc2_send.php)
 * und die API v2 (POST /hc2/channels/{id}/send). Die IPv64 App sendet der hub bzw. die Node selbst (SecNtfy).
 * Nutzt send_mail() und send_sms() aus
 * dbconnect.php; $pdo ist die Verbindung der Webseite. Liefert '' bei Erfolg, sonst eine kurze Fehlermeldung.
 */

use PHPMailer\PHPMailer\PHPMailer;

function hc2_deliver($pdo, string $type, string $to, string $subject, string $text, string $html, string $updown, int $userid): string {
	if (!in_array($updown, array('', '0', '1'), true)) { $updown = ''; }
	switch ($type) {
		case 'mail':
			if (!filter_var($to, FILTER_VALIDATE_EMAIL)) { return 'invalid address'; }
			$mail = new PHPMailer();
			$body = $html !== '' ? $html : nl2br(htmlspecialchars($text));
			if ((new ReflectionFunction('send_mail'))->getNumberOfParameters() >= 9) {
				// send_mail() mit hc2-Option: Betreff und Inhalt unveraendert, eigener Textteil, Ergebnis des Versands
				$ok = send_mail($pdo, $mail, '', 'IPv64.net Healthchecks', $to, $subject !== '' ? $subject : 'IPv64.net Healthchecks', $body, $updown, array('text' => $text));
				$mail->smtpClose();
				return $ok === false ? 'mail not sent' : '';
			}
			// aeltere send_mail(): nimmt freien HTML-Text als Body, wenn er kein Schluesselwort/keine Check-ID ist
			send_mail($pdo, $mail, '', '', $to, $subject !== '' ? $subject : 'IPv64.net Healthcheck', $body, $updown);
			$mail->smtpClose();
			return '';
		case 'sms':
			if (!preg_match('/^[0-9]{6,20}$/', $to)) { return 'invalid number'; }
			send_sms($pdo, json_encode(array('completenumber' => $to)), mb_substr($text, 0, 300), $updown, $userid);
			return '';
	}
	return 'unknown type';
}

/** Mail im ipv64-Design (wie der hub: Kopf, Statusband, Text, Zeilen "Bezeichnung: Wert" als Tabelle, Fusszeile). */
function hc2_mail_html(string $subject, string $text, string $kind, string $lang, string $brand): string {
	$e = function(string $s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); };
	$de = $lang !== 'en';
	$k = strtolower($kind);
	// Balken passend zum Betreff (wie internal/notify/mail.go mailStatus der Node)
	if (preg_match('/(^|_)(up|ok|recovered)$|flapping_end|degraded_end|rechecked|summary_up|threshold_ok/', $k)) { $color = '#2fb344'; $status = $de ? 'Wieder in Ordnung' : 'Recovered'; }
	elseif ($k === 'degraded') { $color = '#f59f00'; $status = $de ? 'Teilweise gestört' : 'Partially down'; }
	elseif (preg_match('/flapping_start|quota|threshold$|expiry|dyndns_limit|unchecked/', $k)) { $color = '#f59f00'; $status = $de ? 'Achtung' : 'Warning'; }
	elseif (preg_match('/fail|down|error|limit|reminder|summary|blocked|honeypot_(watch|login)|dns64_(upstream|lists|cert)$/', $k)) { $color = '#d63939'; $status = $de ? 'Störung' : 'Problem'; }
	else { $color = '#4299e1'; $status = $de ? 'Hinweis' : 'Notice'; }
	$rows = ''; $paras = '';
	foreach (preg_split('/\r?\n/', trim($text)) as $line) {
		$line = trim($line);
		if ($line === '') { continue; }
		$parts = explode(': ', $line, 2);
		if (count($parts) === 2 && mb_strlen($parts[0]) <= 24 && mb_substr($line, 0, 1) !== '•') {
			$rows .= '<tr><td style="padding:6px 12px 6px 0;color:#667382;white-space:nowrap;vertical-align:top">' . $e($parts[0]) . '</td><td style="padding:6px 0;color:#1d273b;word-break:break-word">' . $e($parts[1]) . '</td></tr>';
			continue;
		}
		$paras .= '<p style="margin:0 0 8px 0;color:#1d273b">' . $e($line) . '</p>';
	}
	$auto = $de ? 'Automatische Nachricht von ' . $brand . '.' : 'Automatic message from ' . $brand . '.';
	$manage = $de ? 'Benachrichtigungen verwalten' : 'Manage notifications';
	return '<!DOCTYPE html><html lang="' . ($de ? 'de' : 'en') . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . $e($subject) . '</title></head>'
		. '<body style="margin:0;padding:0;background:#f1f1f1;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5">'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f1f1"><tr><td align="center" style="padding:24px 12px">'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden">'
		. '<tr><td style="padding:18px 24px;border-bottom:1px solid #e6e7e9;font-size:18px;font-weight:bold;color:#17bebb">' . $e($brand) . '</td></tr>'
		. '<tr><td style="padding:10px 24px;background:' . $color . ';color:#ffffff;font-weight:bold;letter-spacing:.3px">' . $e($status) . '</td></tr>'
		. '<tr><td style="padding:20px 24px 8px 24px"><h1 style="margin:0 0 12px 0;font-size:20px;line-height:1.3;color:#1d273b">' . $e($subject) . '</h1>' . $paras
		. ($rows !== '' ? '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px">' . $rows . '</table>' : '') . '</td></tr>'
		. '<tr><td style="padding:14px 24px;border-top:1px solid #e6e7e9;font-size:12px;color:#667382">' . $e($auto) . ' <a href="https://ipv64.net/notifications.php" style="color:#667382">' . $e($manage) . '</a></td></tr>'
		. '</table></td></tr></table></body></html>';
}

/** Handynummer wie der hub (notify.SMSNumber): nur Ziffern, "+" am Anfang = "00", Laendervorwahl Pflicht. */
function hc2_sms_number(string $in): string {
	$in = trim($in); $n = '';
	for ($i = 0, $l = strlen($in); $i < $l; $i++) {
		$c = $in[$i];
		if ($c >= '0' && $c <= '9') { $n .= $c; } elseif ($c === '+' && $i === 0) { $n .= '00'; }
	}
	if ($n === '' || (strncmp($n, '0', 1) === 0 && strncmp($n, '00', 2) !== 0)) { return ''; }
	if (strncmp($n, '00', 2) !== 0) { $n = '00' . $n; }
	return (strlen($n) >= 9 && strlen($n) <= 22) ? $n : '';
}
