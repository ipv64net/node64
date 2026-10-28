# Changelog – Node64

Short summary of what changes per version. Details per module are in the node under Settings → Modules.

## Unreleased

- Security: fixed the findings of a large code review – among others PROXY64 location access lists, hosts via CDN64 only
  under the published name, crashes from crafted packets (Honeypot64 on arm/v7, DNS64), sign-in (memory, redirect,
  X-Forwarded-For, CSRF), backups without program files.
- Healthchecks: incidents, maintenance windows, dependent checks and flapping alert reliably; status pages honour
  "show uptime/history" in JSON too.
- Sync and cluster: large data is split, sync no longer stalls.
- Self-update and certificates: safe rollback, minimum version against the image, public certificates before own CA.
- PROXY64: Docker/Traefik labels with protection that cannot be mapped give a switched-off host instead of an
  unprotected one; fixes to forward auth and API keys.
- DynDNS: confirmation when several names from the account are added at once.

## 0.12.0-alpha.26 – 2026-10-28

- PROXY64: CDN64 statistics explain when there are no protection figures in the period yet.
- PROXY64: TLS per BSI TR-02102-2 selectable per proxy host.
- PROXY64: access lists with authentik, Authelia, oauth2-proxy or an own auth service (forward auth), API keys for apps
  and scripts, user name passed to the target on request. Traefik middlewares with forwardAuth are taken over.
- PROXY64: proxy hosts from Docker labels (`node64.proxy.host`/`port`, optionally Traefik labels too), new Docker tab,
  off by default.
- PROXY64: new defaults for overload protection (fewer connections per IP and in total), hint on the right value per
  device size.
- Sign-in: SSO with authentik works, the issuer URL may end with "/" (#6).
- Honeypot64: the overview numbers stay complete even when the limit of stored events is reached; a hint shows this (#7).

## 0.12.0-alpha.25 – 2026-10-27

- PROXY64: the proxy host list fits on narrower screens.
