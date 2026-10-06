# tgwebproxy

Server for the **WEB** proxy type introduced in Telegram Desktop 7.1.

Telegram shipped a new transport: the app runs a hidden WebView, loads a page
from your domain over ordinary HTTPS, and tunnels multiplexed MTProto traffic
through that page. To an observer the connection is a browser visiting a web
site.

Telegram also published a proof-of-concept server,
[telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server).
This is an independent implementation with different trade-offs — see
[Compared to the reference server](#compared-to-the-reference-server).
[PROTOCOL.md](PROTOCOL.md) is the specification recovered from the client
sources here, cross-checked against the reference server's own protocol
document.

```
Telegram Desktop ──hidden WebView──► bridge page (served by this relay)
                                          │ WebSocket, or plain HTTPS
                                          │ requests where it is blocked
                                          ▼
   capability gate ──► frame demultiplexer ──► obfuscated2 ──► Telegram DC
        └──► cover site for everyone else
```

One static binary does all of it: the cover site, the bridge page, the
WebSocket endpoint, TLS with automatic certificates, and the MTProxy
underneath.

## Quick start

```bash
go build -o tgwebproxy ./cmd/tgwebproxy
```

```bash
./tgwebproxy -domain proxy.example.com -secret 000102030405060708090a0b0c0d0e0f -site ./mysite
```

Point the domain's A record at the host before starting: the certificate is
obtained from Let's Encrypt on the first TLS handshake. Without `-secret` the
relay generates one and prints it; without `-site` it serves a built-in page
(replace it, see [Camouflage](#camouflage)).

The relay prints what to enter in the client:

```
  Telegram Desktop -> Settings -> Advanced -> Connection type -> Add proxy -> WEB

    Web proxy hostname : proxy.example.com
    Secret (default) : 000102030405060708090a0b0c0d0e0f
      https://t.me/webproxy?secret=000102030405060708090a0b0c0d0e0f&server=proxy.example.com
```

The link configures the client in one step, which beats dictating thirty-two
hex characters. `t.me` does not route this path yet, so it may have to be
opened inside Telegram rather than from a browser.

### Configuration

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-domain` | `TGWP_DOMAIN` | — | domain the relay answers on (required) |
| `-secret` | `TGWP_SECRET` | generated | 16-byte secret, hex or base64url; `dd` prefix selects padded intermediate |
| `-site` | `TGWP_SITE` | built-in | directory with the cover site (`index.html` required) |
| `-cert-dir` | `TGWP_CERT_DIR` | `certs` | ACME certificate cache |
| `-listen` | `TGWP_LISTEN` | `:443` | TLS address (`127.0.0.1:4600` when behind a proxy) |
| `-plain-listen` | `TGWP_PLAIN_LISTEN` | `:80` | HTTP→HTTPS redirect and HTTP-01; empty disables |
| `-behind-proxy` | `TGWP_BEHIND_PROXY` | off | plain HTTP for a front end that terminates TLS |
| `-max-streams` | — | 64 | concurrent MTProto streams per session |
| `-diagnose` | `TGWP_DIAGNOSE` | off | one log line per request, never the capability |
| `-log-level` | `TGWP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

For more than one client, use a configuration file instead of flags:

```bash
./tgwebproxy -config /etc/tgwebproxy/relay.toml
```

```toml
domain = "proxy.example.com"

[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
label = "phone"

[[secret]]
value = "0f0e0d0c0b0a09080706050403020100"
label = "laptop"
```

Each client gets its own secret, so one can be revoked without disturbing the
others, and logs name the client rather than the address. Client blocks also
accept `disabled`, `expires_unix` and `quota_bytes`. Disabled or expired
clients cannot authenticate; a quota is counted as upload + download bytes and
an active session is closed when the limit is reached.
[relay.example.toml](relay.example.toml) lists every setting. `-config` cannot
be combined with `-domain` or `-secret`: the file is either the source of truth
or it is not used at all.

### Several domains

One process can serve any number of names, each with its own secrets and cover
site:

```toml
[[host]]
name = "files.example.com"
site = "/srv/site-files"
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"
  label = "phone"

[[host]]
name = "media.example.net"
site = "/srv/site-media"
  [[host.secret]]
  value = "0f0e0d0c0b0a09080706050403020100"
  label = "laptop"
```

Blocking a proxy by domain name is cheap, and no amount of camouflage inside
the connection changes that. What helps is making domains plural and cheap to
replace: when one is blocked the user edits a single field in the client, keeps
the same secret, and the server is not touched. One certificate is obtained per
name, and a capability minted for one name is refused by the others.

The two shapes cannot be mixed: either a top-level `domain` or `[[host]]`
blocks. With several domains the `Host` header is what tells them apart, so a
front end must pass it through unchanged; with a single domain any `Host` is
accepted, because there is nothing to route.

`SIGHUP` reloads the secrets and cover site of every domain, plus
`max_streams` and `log_level` — `docker kill -s HUP <container>`. **Sessions
belonging to a removed secret are disconnected**, while renaming a secret
leaves its session alone. Adding or removing a domain needs a restart, as do
the listen addresses, `cert_dir` and `behind_proxy`; such a change is refused,
as is a file that does not parse, and the running configuration stays in place
either way.

`ee` (fake-TLS) secrets are rejected: Telegram Desktop marks them unsupported
for this proxy type, since HTTPS already does what fake-TLS exists for.

### Docker

```bash
docker build -t tgwebproxy .
```

```bash
docker run -d --name tgwebproxy -p 80:80 -p 443:443 -v certs:/certs \
  -e TGWP_DOMAIN=proxy.example.com -e TGWP_SECRET=<hex> tgwebproxy
```

Keep the `/certs` volume, or every restart asks Let's Encrypt for a new
certificate and hits its rate limit.

### MAIN + HTTPS edge

For a censored edge, keep `tgwebproxy` on the MAIN host and expose it only on
loopback with `behind_proxy = true`. A separate edge VPS can terminate
`web.example.com` and reverse-proxy ordinary HTTPS/WebSocket traffic to MAIN
over TLS. Preserve the original HTTP `Host` because WEB capabilities are bound
to the public hostname. The edge does not need client secrets and does not
connect to Telegram directly.

### Behind nginx

When something else already owns port 443, let it terminate TLS and proxy to
the relay on the loopback:

```bash
./tgwebproxy -domain proxy.example.com -secret <hex> -behind-proxy
```

The relay listens on `127.0.0.1:4600` and obtains no certificate. The domain
is still required — the capability is bound to it and the bridge page builds
its `wss://` URL from it. The vhost must forward the WebSocket upgrade
(`Upgrade`/`Connection` headers) and should keep the query string out of the
access log, because the capability is a bearer credential.

## When a WebSocket does not survive

The bridge page tries a WebSocket first and, if it does not come up, carries
the same session over ordinary HTTPS requests: numbered `POST` batches for the
uplink, and a `GET` the relay holds open until it has something to send. The
relay above the carrier cannot tell the two apart, and the client twin enforces
the same rules over both.

The page decides, not the server. A network where a WebSocket is blocked or
silently held open is discovered at runtime by the page that is already
running, which is one advantage of the carrier being ours to choose: the
reference server picks a mode per profile at start-up instead.

Uplink batches carry a sequence number and downlink polls a cursor. This is not
bookkeeping for its own sake — an HTTP request can be retried by anything in
the path, and a batch applied twice would inject the same MTProto bytes twice
and desynchronise the stream. A repeat of the previous number is answered from
the previous result; a gap is refused outright.

## Health and metrics

```toml
[admin]
listen = "127.0.0.1:9600"
# token = "strong-random-token" # enables the private 3x-ui client API
# state_file = "/var/lib/tgwebproxy/clients.json" # persists API-managed clients
```

`/healthz` says the process is alive, `/readyz` opens and drops a TCP
connection to a data centre — the one question a process cannot answer about
itself — and `/metrics` serves the Prometheus text format with no dependency
behind it:

```
tgwp_sessions_active{domain="files.example.com",label="phone"} 1
tgwp_bytes_up_total{domain="files.example.com",label="phone"} 148213
tgwp_bytes_down_total{domain="files.example.com",label="phone"} 9930118
tgwp_streams_opened_total{domain="files.example.com",label="phone"} 12
tgwp_upstream_dial_failures_total{domain="files.example.com",label="phone"} 0
tgwp_gate_rejections_total{domain="files.example.com"} 431
```

Because every series carries the secret's label, traffic is attributed per
client.

When `[admin].token` is set, the same private listener also exposes a
bearer-protected management endpoint for 3x-ui:

```text
GET /clients
PUT /clients
Authorization: Bearer <token>
```

`PUT /clients` is desired-state sync for one configured domain: it atomically
replaces that domain's client list with `name`, `secret`, `enabled`,
`expires_unix` and `quota_bytes`. Removed, disabled or expired clients lose
their live sessions. `GET /clients` returns the active policy plus per-client
upload/download and live session/stream counters. When `state_file` is set, API-managed client policy is atomically persisted
and restored over the TOML bootstrap configuration after a process restart.
The state file contains client secrets and accumulated upload/download usage and is
written with mode `0600`; place it on a durable private volume. Usage is
checkpointed every 5 seconds and flushed on graceful shutdown, so quotas survive
normal service restarts; an abrupt host/process crash can lose at most the most
recent checkpoint interval. The endpoint is never registered on the public
listener.

The listener must be private — a loopback `host:port`, or a filesystem path
taken as a Unix socket. Anything routable is refused at start-up, and a test
asserts these paths do not exist on 443: an admin endpoint on the public port
would be a fingerprint that undoes the gate.

**In Docker, use the socket.** A container that binds its own loopback cannot
have that port published, so `-p 127.0.0.1:9600:9600` reaches nothing. Put the
socket on a bind-mounted directory instead:

```toml
[admin]
listen = "/run/tgwebproxy/admin.sock"
```

```bash
docker run ... -v /run/tgwebproxy:/run/tgwebproxy tgwebproxy -config /conf/relay.toml
curl --unix-socket /run/tgwebproxy/admin.sock http://admin/metrics
```

At start-up the relay also checks itself and says so in the log: whether this
host can reach a data centre at all, whether `behind_proxy` is set while
listening beyond the loopback, whether the certificate cache is writable, and
whether a domain is still serving the built-in placeholder page.

## Checking a deployment

```bash
go run ./cmd/tgwebproxy-probe -domain proxy.example.com -secret <hex>
```

The probe fetches the cover page, confirms that a wrong capability is answered
byte-for-byte the same, opens the bridge and the socket, performs the client's
transport handshake while enforcing every rule the client enforces, and then
completes a real `req_pq_multi`/`resPQ` exchange with a Telegram data centre
through the relay. A relay that passes is moving Telegram's own bytes end to
end.

## Camouflage

The transport exists so that the domain looks ordinary. The relay is built
around that:

- The bridge page and the WebSocket both live on `/`. There is no second path
  to find.
- Every request runs the same constant-time capability check. A wrong or
  missing capability produces the cover site — same status, same headers, same
  bytes. There is no `403` and no timing difference; a test enforces this.
- A stream whose MTProto handshake fails is closed without explanation.
- Nothing is logged per request unless `-diagnose` is on, and even then the
  capability is never written.

What the relay cannot do is make the cover site convincing. Point `-site` at
something you would plausibly host on that domain.

## How it works

| Package | Responsibility |
|---|---|
| `cmd/tgwebproxy` | flags, wiring, graceful shutdown |
| `cmd/tgwebproxy-probe` | deployment check against a live relay |
| `internal/httpfront` | TLS/ACME, capability gate, cover site, WebSocket upgrade |
| `internal/webassets` | bridge page and built-in cover page |
| `internal/frame` | the 8-byte frame and the client's limits |
| `internal/relay` | session, stream multiplexing, flow control, keepalive |
| `internal/mtproto` | obfuscated2 in both directions |
| `internal/dc` | data-centre id → address |
| `internal/secret` | secret parsing, bridge capability |
| `internal/hostname` | the client's host normalisation |
| `internal/twin` | a Telegram Desktop stand-in that enforces the client's rules |
| `e2e` | the whole stack over real TLS against the twin |

The design follows one principle: the client is unforgiving, so the relay must
be too. A single unexpected frame makes Telegram Desktop drop the whole
transport — every stream in it, not just the offending one. So the relay
reserves window credit before it reads from a data centre, and refuses to send
any frame type the client has no handler for.

## Development

```bash
go test -race ./...
```

The suite pins the constants and the two capability vectors compiled into
tdesktop, covers the handshake in both directions, the flow-control rules,
the indistinguishability of the gate, and an end-to-end run over TLS against
the client twin.

## Compared to the reference server

Telegram's [tproxy-server](https://github.com/telegramdesktop/tproxy-server) is
the reference implementation, and it is the one to read if you want the
protocol from the source. It is also a proof of concept with **no license
file**, which means no one may legally redistribute or fork it.

The two answer different questions. The reference relay terminates the carrier
and hands the demultiplexed streams to a **stock official MTProxy running
beside it**; its installer builds MTProxy from a pinned commit, installs Caddy,
four systemd units and nftables rules, and targets x86_64 Debian or Ubuntu.
This relay speaks obfuscated2 itself and dials the data centres directly, so it
is one static binary with no companion processes.

| | this relay | tproxy-server |
|---|---|---|
| License | MIT | none (all rights reserved) |
| Data-centre leg | built in | delegated to a stock MTProxy |
| Needs Caddy/nginx | no, ACME built in | yes, Caddy owns 443 |
| Deployment | any Go target, Docker | x86_64 Debian/Ubuntu installer |
| Data-centre transport | IPv4 with IPv6 fallback | whatever MTProxy does |
| Carriers | WebSocket, HTTP long poll, chosen by the page | WebSocket, HTTP long poll, per-stream lanes, chosen by the server |
| Frame batching | one frame per message | up to 4096 frames per message |
| Cover site | static directory or built-in | static directory or loopback upstream |
| Secrets | any number, hot reload and revocation | up to 32 profiles, restart to change |
| Domains per process | any number | one (an explicit non-goal for v1) |

Where the reference is ahead, it is ahead for good reasons: the HTTP long-poll
carriers keep working where WebSocket does not, and batching costs it nothing.
Both are worth having here and neither is implemented yet.

## Status

Working with Telegram Desktop. The protocol was read off the `dev` branch of
tdesktop at release 7.1.1 and checked against the reference server's
`PROTOCOL.md` — frame format, limits and capability vectors agree — and a real
client has since connected through a deployed relay and carried traffic.

The automated checks stand behind that: the probe completes `req_pq_multi`
against a production data centre over both carriers, and the test suite drives
the whole stack against a twin that enforces the client's own strictness frame
by frame.

## License

MIT.
