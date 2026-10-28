# Changes – Sonar64

## 0.1.0 – 2026-10-28

First version of the Sonar64 community measurement network as an optional module (off by default).

### New
- Opt-in participation with the central ipv64 API key: Node64 creates a dedicated Sonar token for it (stored
  encrypted) and measures according to the signed plan from ipv64.net, within fixed limits.
- Role "outbound only" (default) or "also measured" (UDP 6464, via port management), budget low/normal/generous,
  quiet hours.
- Profile at ipv64: display name, location (published blurred to about 1 km), access type, device.
- Trust level as a coloured badge with progress to the next level, link to the public node page.
- Live tables "my pings" (every 5 seconds) and "pings to me" (UDP 6464 instantly, otherwise from the results at ipv64).
- Local API `/api/sonar64/status`, `recent`, `inbound`, `settings`.
