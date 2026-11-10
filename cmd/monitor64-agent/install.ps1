# Monitor64-Agent installieren (Windows 10/11, Server 2016 und neuer, amd64). Den Befehl mit dem Schluessel der Node
# zeigt Node64 im Assistenten "Host hinzufuegen"; in einer PowerShell als Administrator:
#
#   [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((irm https://node64.de/agent/install.ps1))) -Key "ssh-ed25519 AAAA... node64@nas"
#
# Der Teil vor dem Semikolon schaltet TLS 1.2 ein (3072 = Tls12), bevor irm dieses Skript laedt: Windows PowerShell
# 5.1 auf Server 2016 und aelteren Windows-10-Staenden spricht sonst nur TLS 1.0/1.1, und der Abruf scheitert an
# Servern, die nur TLS 1.2 und neuer anbieten - die Umschaltung weiter unten im Skript kaeme dafuer zu spaet.
#
# Optionen: -Key "<oeffentlicher Schluessel>" (Pflicht), -Port 6465, -Base <URL> (Ordner mit den Dateien, Standard
# https://node64.de/agent/; z. B. die eigene Node fuer Hosts ohne Internet).
# Push-Betrieb (Host hinter NAT, VPS): -Connect "token@node[:6466]" (auch mehrere, durch Komma) baut die Verbindung
# zur Node selbst auf; -NoListen zusaetzlich, wenn der Agent nicht lauschen soll (dann auch keine Firewall-Regel).
# -NoTray: kein Symbol im Infobereich der Taskleiste (sonst zeigt der Dienst es jedem angemeldeten Benutzer:
# laeuft, Version, letzte Abfrage, Update verfuegbar).
# Die Datei monitor64-agent-windows-amd64.exe wird gegen SHA256SUMS aus demselben Ordner geprueft und ruft dann
# "monitor64-agent install" auf (Datei, Schluessel, Dienst, Firewall-Regel, Fingerabdruck des Hostschluessels).
# Entfernen: & "$env:ProgramFiles\monitor64-agent\monitor64-agent.exe" uninstall
#
# Fehler werden mit throw gemeldet (kein exit: der wuerde beim Einzeiler die ganze PowerShell schliessen).
param(
    [Parameter(Mandatory = $true)][string]$Key,
    [int]$Port = 0,
    [string]$Base = 'https://node64.de/agent/',
    [string[]]$Connect = @(),
    [switch]$NoListen,
    [switch]$NoTray
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Say([string]$Msg) { Write-Host "monitor64-agent: $Msg" }

$Key = $Key.Trim()
if (-not $Key) { throw 'monitor64-agent: -Key is missing (public key of the node, shown in Node64)' }
if ($Port -lt 0 -or $Port -gt 65535) { throw "monitor64-agent: invalid port: $Port" }
foreach ($c in $Connect) {
    if ($c -notmatch '^[a-z0-9]{16,64}@[A-Za-z0-9.:_\[\]-]+$') { throw "monitor64-agent: invalid -Connect value: $c (token@host[:port])" }
}
if ($NoListen -and $Connect.Count -eq 0) { throw 'monitor64-agent: -NoListen needs -Connect "token@node[:port]"' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'monitor64-agent: please run PowerShell as Administrator'
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { }
    'ARM64' { Say 'WARNING: ARM64 - using the amd64 build (runs in emulation)' }
    default { throw "monitor64-agent: unsupported architecture: $arch" }
}
$File = 'monitor64-agent-windows-amd64.exe'

# Bei HTTPS keine Umleitung auf HTTP (sonst koennte jemand Datei und SHA256SUMS gemeinsam austauschen).
if ($Base -like 'https://*') {
    $https = $true
} elseif ($Base -like 'http://*') {
    $https = $false
    Say 'WARNING: downloading over plain HTTP - the checksum only protects against broken downloads, not against tampering. Use HTTPS if possible.'
} else {
    throw 'monitor64-agent: -Base must start with https:// or http://'
}
if (-not $Base.EndsWith('/')) { $Base += '/' }

# Windows PowerShell 5.1 auf aelteren Systemen spricht sonst nur TLS 1.0 (fuer die Downloads, auch wenn das Skript
# ohne die Zeile aus dem Kopf geladen wurde)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Fetch laedt eine URL in eine Datei: Zeitlimits (Verbindung 10 s, Lesen 300 s), hoechstens 5 Umleitungen, bei HTTPS
# keine Umleitung auf HTTP.
function Fetch([string]$Url, [string]$Out) {
    for ($i = 0; $i -lt 5; $i++) {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.AllowAutoRedirect = $false
        $req.Timeout = 10000
        $req.ReadWriteTimeout = 300000
        $req.UserAgent = 'monitor64-agent-install'
        try {
            $resp = $req.GetResponse()
        } catch [Net.WebException] {
            $resp = $_.Exception.Response
            if (-not $resp) { throw "monitor64-agent: download failed: $Url ($($_.Exception.Message))" }
        }
        $code = [int]$resp.StatusCode
        if ($code -ge 300 -and $code -lt 400) {
            $loc = $resp.Headers['Location']
            $resp.Close()
            if (-not $loc) { throw "monitor64-agent: redirect without location: $Url" }
            $next = New-Object Uri((New-Object Uri($Url)), $loc)
            if ($https -and $next.Scheme -ne 'https') { throw 'monitor64-agent: redirect to plain HTTP refused' }
            $Url = $next.AbsoluteUri
            continue
        }
        if ($code -ne 200) {
            $resp.Close()
            throw "monitor64-agent: download failed: $Url (HTTP $code)"
        }
        $in = $resp.GetResponseStream()
        $fs = [IO.File]::Create($Out)
        try { $in.CopyTo($fs) } finally { $fs.Close(); $in.Close(); $resp.Close() }
        return
    }
    throw "monitor64-agent: too many redirects: $Url"
}

# Download in den Programmordner (nur Administratoren duerfen dort schreiben), nicht nach %TEMP%.
$ProgDir = Join-Path $env:ProgramFiles 'monitor64-agent'
New-Item -ItemType Directory -Force -Path $ProgDir | Out-Null
$Tmp = Join-Path $ProgDir ('.download-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    $exe = Join-Path $Tmp 'monitor64-agent.exe'
    $sums = Join-Path $Tmp 'SHA256SUMS'
    Say "downloading $Base$File"
    Fetch ($Base + $File) $exe
    Fetch ($Base + 'SHA256SUMS') $sums

    $want = $null
    foreach ($line in [IO.File]::ReadAllLines($sums)) {
        $f = $line.Trim() -split '\s+'
        if ($f.Count -ge 2 -and ($f[1] -eq $File -or $f[1] -eq ('*' + $File))) { $want = $f[0].ToLower(); break }
    }
    if (-not $want) { throw "monitor64-agent: $File not listed in SHA256SUMS" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLower()
    if ($got -ne $want) { throw "monitor64-agent: checksum mismatch for $File (expected $want, got $got)" }
    Say 'checksum ok'

    $installArgs = @('install', '--key', $Key)
    if ($Port -gt 0) { $installArgs += @('--port', [string]$Port) }
    foreach ($c in $Connect) { $installArgs += @('--connect', $c) }
    if ($NoListen) { $installArgs += '--no-listen' }
    if ($NoTray) { $installArgs += '--no-tray' }
    & $exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "monitor64-agent: install failed (exit code $LASTEXITCODE)" }
} finally {
    Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
}
