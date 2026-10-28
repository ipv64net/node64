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
- Fast onboarding: plan every 2 minutes (unchanged plans only cost a short answer), report every 5 minutes.
- "Leave" signs the node off at ipv64.net and deletes token, key and node ID; if ipv64.net is not reachable, the node
  still leaves locally (ipv64.net signs off nodes after 30 days without reports). "Reset node" leaves as well.
- Signed off by ipv64.net (token revoked, disabled, 30 days without reports): the node stops measuring, closes UDP
  6464 and checks hourly; the page shows "Signed off by ipv64.net" with "Participate again" (new token).
- Local API `/api/sonar64/status`, `recent`, `inbound`, `settings`.
