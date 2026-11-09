package m64win

// Feste PowerShell-Skripte fuer die langsamen Abschnitte. Sie nehmen keine Eingaben von aussen an, lesen nur und
// geben genau ein JSON-Dokument aus; Fehler stehen im JSON ("errors" bzw. "fatal"), nicht auf stderr. Laufen mit
// Windows PowerShell 5.1 (in jedem Windows ab 10/Server 2016 enthalten).

// psPrologue: UTF-8-Ausgabe, keine Fortschrittsanzeige, Fehler als Ausnahme.
const psPrologue = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
`

// storageScript liest die Platten (Get-PhysicalDisk, Zuverlaessigkeitszaehler - die brauchen Adminrechte) und die
// virtuellen Datentraeger von Storage Spaces samt Mitgliedern.
const storageScript = psPrologue + `try {
  $r = [ordered]@{ disks = @(); vdisks = @(); errors = @() }
  $pds = @()
  try { $pds = @(Get-PhysicalDisk) } catch { $r.errors += 'Get-PhysicalDisk: ' + $_.Exception.Message }
  foreach ($d in $pds) {
    $c = $null; $ce = ''
    try { $c = $d | Get-StorageReliabilityCounter } catch { $ce = $_.Exception.Message }
    $r.disks += [ordered]@{
      id = [string]$d.DeviceId; name = [string]$d.FriendlyName; serial = ([string]$d.SerialNumber).Trim()
      bus = [string]$d.BusType; media = [string]$d.MediaType; size = $d.Size
      health = [string]$d.HealthStatus; op = @($d.OperationalStatus | ForEach-Object { [string]$_ })
      temp = $c.Temperature; wear = $c.Wear; poh = $c.PowerOnHours
      rerr = $c.ReadErrorsUncorrected; werr = $c.WriteErrorsUncorrected; cerr = $ce
    }
  }
  try {
    foreach ($v in @(Get-VirtualDisk)) {
      $m = @(); try { $m = @($v | Get-PhysicalDisk) } catch {}
      $r.vdisks += [ordered]@{
        name = [string]$v.FriendlyName; level = [string]$v.ResiliencySettingName
        health = [string]$v.HealthStatus; op = @($v.OperationalStatus | ForEach-Object { [string]$_ })
        members = @($m | ForEach-Object { [ordered]@{ name = [string]$_.FriendlyName; health = [string]$_.HealthStatus } })
      }
    }
  } catch { $r.errors += 'Get-VirtualDisk: ' + $_.Exception.Message }
  ConvertTo-Json -InputObject $r -Depth 5 -Compress
} catch { ConvertTo-Json -Compress -InputObject @{ fatal = $_.Exception.Message } }
`

// raidScript liest nur die virtuellen Datentraeger (oefter, wenn welche vorhanden sind).
const raidScript = psPrologue + `try {
  $r = [ordered]@{ disks = @(); vdisks = @(); errors = @() }
  try {
    foreach ($v in @(Get-VirtualDisk)) {
      $m = @(); try { $m = @($v | Get-PhysicalDisk) } catch {}
      $r.vdisks += [ordered]@{
        name = [string]$v.FriendlyName; level = [string]$v.ResiliencySettingName
        health = [string]$v.HealthStatus; op = @($v.OperationalStatus | ForEach-Object { [string]$_ })
        members = @($m | ForEach-Object { [ordered]@{ name = [string]$_.FriendlyName; health = [string]$_.HealthStatus } })
      }
    }
  } catch { $r.errors += 'Get-VirtualDisk: ' + $_.Exception.Message }
  ConvertTo-Json -InputObject $r -Depth 5 -Compress
} catch { ConvertTo-Json -Compress -InputObject @{ fatal = $_.Exception.Message } }
`

// updatesScript sucht ausstehende Updates ueber die Windows-Update-API (wie "Einstellungen > Windows Update",
// beachtet WSUS); sicherheitsrelevant: mit MSRC-Einstufung oder in der Kategorie "Security Updates".
const updatesScript = psPrologue + `try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $s.ClientApplicationID = 'monitor64-agent'
  $res = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $n = 0; $sec = 0
  foreach ($u in $res.Updates) {
    $n++
    $isSec = [bool]$u.MsrcSeverity
    foreach ($c in $u.Categories) { if ($c.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441') { $isSec = $true } }
    if ($isSec) { $sec++ }
  }
  $reboot = $false
  try { $reboot = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
  ConvertTo-Json -Compress -InputObject ([ordered]@{ pending = $n; security = $sec; reboot = $reboot })
} catch { ConvertTo-Json -Compress -InputObject @{ fatal = $_.Exception.Message } }
`

// Scripts liefert die PowerShell-Skripte zum Anzeigen ("Was wird abgefragt?").
func Scripts() map[string]string {
	return map[string]string{"storage": storageScript, "raid": raidScript, "updates": updatesScript}
}
