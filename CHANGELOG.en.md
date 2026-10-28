# Changelog – Node64

Short summary of what changes per version. Details per module are in the node under Settings → Modules.

## Unreleased

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
