//go:build windows

package main

// defaultDir enthaelt keys, hostkey, local.d und das Protokoll des Dienstes (agent.log); nur SYSTEM und
// Administratoren haben Zugriff (install setzt die Rechte).
const defaultDir = `C:\ProgramData\monitor64-agent`
