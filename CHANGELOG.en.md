# Changelog – Node64

Short summary of what changes per version. Details per module are in the node under Settings → Modules.

## Unreleased

- Cluster: when pairing, an outdated API key no longer wins over a newer one in the cluster, and removing the key
  also reaches members that were unreachable while a new node was paired. Rejected entries are retried with a growing
  interval (up to 6 h) and are no longer lost when fetching is interrupted.
- PROXY64: bandwidth per proxy host, "TLS pass-through" and stream – limit download and upload in Mbit/s (unlimited by default), above
  it traffic is slowed down instead of cut off.
- PROXY64: streams in one table – names for streams only with their CDN64 state and their ports together.
- Certificates: domain plus wildcard via DuckDNS, Hurricane Electric or RFC2136 work again (these providers hold only
  one TXT value and are checked one after another again). The DNS-01 check also requires several stable rounds via
  public resolvers, and a value that becomes stable shortly before the deadline still counts.

## 0.12.0-alpha.31 – 2026-10-29

- Database: the last three backups before migrations are kept instead of five (saves several hundred MB per node).
- PROXY64: names for streams only – a stream (TCP/UDP) goes to the internet via CDN64 without a proxy host or target;
  neither HTTP nor HTTPS answers under the name.
- Security: databases (node, DNS64 query log, PROXY64 statistics) and their backups are readable only by the node
  user (before 0644, readable by every user on the host); existing files are fixed at startup.
- Certificates: domain plus wildcard (`example.ipv64.de` + `*.example.ipv64.de`) via DNS-01 failed at Let's Encrypt
  ("Incorrect TXT record"); both challenge values are now set at the same time, and Node64 waits until all
  nameservers return the value several times in a row (the ipv64 nameservers briefly alternate old and new).
- Healthchecks: a change from the portal made at the same time as a change on the node was lost on the node; it now
  arrives (also needs the new hubs).
- Healthchecks/cluster: changes of a node without link made outside the cluster reach the portal right after
  rejoining (before only after a restart).
- Settings → Logging: "Log API requests" (opt-in: off, API key only or all). Every request to /api/ then shows up
  as a log line with method, path, status, duration, IP, user and API key name – no contents, secrets masked. Also
  via `PUT /api/logging` (`api_log`).
- Healthchecks/cluster: nodes without their own ipv64 link can create and edit online and hybrid checks when a
  linked node in the cluster is reachable.
- Cluster: when a node with an API key joins a cluster in which the key was removed earlier, the others take its
  key – before, the joining node lost it. A node without a key that moves to another cluster no longer removes the
  key there.
- Cluster: a rejected entry (e.g. status page with the same slug, user to choose) is retried every 5 minutes and
  arrives once the conflict is resolved on one side – before, only after it changed again on the other node.
- Healthchecks: Proxmox VE and Docker – "Stopped is correct" on a stopped or exited guest shown as a problem: one
  click and the state is fine (no all-clear message). A backup that briefly starts a stopped guest no longer makes it
  "should run" (previously a false "stopped" alert after the backup).

## 0.12.0-alpha.30 – 2026-10-28

- Healthchecks: Proxmox VE and Docker checks show a real latency (ping to node, guest or container, otherwise the API
  response time) instead of 0 ms.
- Certificates/cluster: identical entries (certificate with key, ACME CA with EAB, DNS account, CA) are merged once
  when joining, merely similar ones stay separate; different ACME accounts are no longer overwritten but offered for
  choice on the cluster page.
- Cluster: new areas "Status pages" and "Channels" (notifications, mainly for nodes without ipv64.net), off by
  default; items set up exactly the same on two nodes beforehand are merged instead of appearing twice.
- Cluster: new module “Node” (off by default) – enter the ipv64 API key only once (same account or the node has none
  yet, never another one; takeover in the audit log) and sync general settings (time zone, self-update, MCP on/off).
- Cluster: nodes without an ipv64 account can join a cluster with an account; a node getting the cluster's account
  (e.g. via the API key) or losing it no longer suspends anything. Two different accounts in one cluster are still
  never possible.
- Cluster: new area "Users & login" (users with password, 2FA and SSO links, SSO setup), off by default; passkeys,
  sessions and forward auth stay per node, users with the same name but different content are offered for choice on
  the cluster page, the last user of a node is never deleted. Other users of the node can be deleted under Login.
- DynDNS/cluster: new area "DynDNS" (off by default) syncs names and settings; only one node updates at a time, if it
  fails another one takes over automatically (preferred node selectable on the DynDNS page).

## 0.12.0-alpha.29 – 2026-10-28

- Internal improvements.

## 0.12.0-alpha.28 – 2026-10-28

- Internal improvements.

## 0.12.0-alpha.27 – 2026-10-28

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
- Healthchecks: checks measured only by this node are alerted by the node itself even when linked (ipv64 mail/SMS/app
  via the API, own channels directly); other portal channels are still sent by ipv64.

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
