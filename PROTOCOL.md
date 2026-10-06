# Telegram WEB proxy: the wire protocol

Telegram Desktop 7.1 (21 Aug 2026) added a proxy type called **WEB**. This
document is the server-side specification, recovered from the client sources
and verified by the relay in this repository. Every rule below is something the
client enforces; where it matters, the tdesktop symbol that enforces it is
named so you can check it yourself.

Telegram later published a proof-of-concept server,
[telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server),
with a protocol document of its own. Everything here has been cross-checked
against it: the frame format, the limits and the capability vectors agree.
Where the two describe different things, this document says so — the reference
server defines its own page-to-server carrier, which no client requires.

Sources (tdesktop, branch `dev`, `Telegram/SourceFiles/mtproto/`):

| File | What it defines |
|---|---|
| `web_proxy/web_proxy_frame.{h,cpp}` | frame layout, limits, parser |
| `web_proxy/web_proxy_transport.{h,cpp}` | session state machine, streams, flow control, carriers |
| `web_proxy/web_proxy_webview.{h,cpp}` | hidden WebView, injected `TelegramWebProxy` bridge |
| `details/mtproto_web_proxy_socket.{h,cpp}` | the socket that replaces TCP for a WEB proxy |
| `mtproto_proxy_data.{h,cpp}` | host normalisation, secret validation, capability |
| `connection_tcp.cpp` | obfuscated2 prefix, unchanged for WEB |
| `session_private.cpp` | DC id encoding |

## 1. The idea

The client starts a hidden WebView, loads `https://<host>/` from the proxy
domain, and lets the page it gets back carry bytes for it. The page opens a
WebSocket to its own origin and forwards binary messages in both directions
without looking at them. Inside those messages the client multiplexes several
MTProto connections, each of which is an ordinary MTProxy (obfuscated2) stream.

To the network it is a browser visiting a web site. To the server it is:

```
GET /?bridge=<capability>        → the bridge page (HTML + JS)
GET /?bridge=<capability>        → WebSocket upgrade from that page
   └─ binary messages: frames   → multiplexed streams → obfuscated2 → Telegram DC
```

Anything else the server receives must be answered like an ordinary web site.

## 2. Proxy parameters

The user enters a hostname and a secret. The client validates them in
`ProxyData::status()` for `Type::Web`:

- **host** — a domain name, normalised by `NormalizeWebProxyHost`:
  trim; reject if it contains `:`, `/`, `?`, `#` or `@` or ends with `.`;
  `QUrl::toAce` (punycode), then lowercase; reject if empty, longer than 253,
  or without a dot; each label 1–63 characters of `[a-z0-9-]` not starting or
  ending with `-`; reject if the last label is numeric (so `127.1`, `0x7f.1`
  and dotted decimals are out) or the whole thing parses as an IP address.
  `localhost` is rejected because it has no dot.
- **port** — must be 443.
- **user** — must be empty.
- **secret** — hex or base64url, in the MTProxy shapes:
  16 bytes (obfuscated2 + abridged), or `dd` + 16 bytes (obfuscated2 + padded
  intermediate). An `ee` fake-TLS secret is valid syntax but `Status::Unsupported`
  for this type.

The server must apply the same normalisation to its configured domain, because
the normalised spelling is what gets hashed in the next step.

## 3. The capability

The bridge page is gated by a value derived from the secret and the host:

```
capability = base64url_nopad( HMAC-SHA256( key = secret_bytes,
                                           msg = "tdesktop-web-proxy-bridge-v1\n" + host ) )
```

`secret_bytes` is the decoded secret **including** the `dd` prefix when
present. `host` is the normalised host. The client ships two test vectors in a
debug assertion (`WebProxyBridgeCapability`), host `proxy.example.com`:

| secret | capability |
|---|---|
| `000102030405060708090a0b0c0d0e0f` | `MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk` |
| `dd000102030405060708090a0b0c0d0e0f` | `IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA` |

The capability is a bearer credential: whoever has it gets the bridge page.
Compare it in constant time and never write it to a log.

## 4. Two carriers, one page

The client has two ways to run the bridge page. The server serves the same
page for both; the page detects which one it is in with `window.top === window`.

### 4.1 Hidden WebView (normal path)

URL: `https://<host>/?bridge=<capability>#android=<nonce>`, nonce = 32 random
bytes, base64url. The fragment never reaches the server.

The WebView is opened with `restrictedOrigin = https://<host>`; navigation to
any other URL fails the carrier. The profile is restricted: expect
`WebAssembly`, `RTCPeerConnection` and `WebTransport` to be undefined. Plain
`WebSocket`, `fetch` and `XMLHttpRequest` work.

Before the page loads, the client injects a frozen `window.TelegramWebProxy`
(see `BridgeScript()`):

| Member | Direction | Meaning |
|---|---|---|
| `postMessage(ArrayBuffer)` | page → app | one or more frames |
| `postMessage(string)` | page → app | JSON control message |
| `onmessage = fn` | app → page | `fn({data})`, `data` is `ArrayBuffer` (frames) or `string` (control) |

The page must:

1. Set `TelegramWebProxy.onmessage`.
2. Read the nonce from `location.hash` and post
   `{"t":"tproxy-android-init","v":1,"nonce":"<nonce>"}` — `v` must be `1`
   and the nonce must match, which proves the page actually read the fragment.
3. Forward every `ArrayBuffer` it receives to the server and every binary
   WebSocket message to `postMessage`.

The client delivers one frame per native message and waits for the injected
script's acknowledgement before sending the next (`kWriteTimeout` 10 s). In the
other direction a native message may carry a batch: the reference relay packs
up to 4096 frames into one and its page forwards the message whole. The first
binary message the page posts back must still be exactly one `Welcome` frame
(§6).

Optional control messages from the page: `{"t":"status","state":S}` with `S`
one of `connecting`, `reconnecting`, `connected`, `failed`; the first two extend
the handshake timer (10 s, up to 45 s total), `failed` fails the carrier.
`{"t":"close"}` fails the carrier. On shutdown the app sends
`{"t":"close"}` to the page.

Timers: `kHandshakeTimeout` 10 s, `kHandshakeTotalTimeout` 45 s,
`kHealthTimeout` 10 s without any native message (the app itself injects a
heartbeat every 3 s; the page does nothing for this). Retry with backoff
2 s → 30 s; after `kMaxWebviewFailures = 3` the client offers the browser
fallback.

### 4.2 System browser (fallback)

The client starts a local HTTP server on `127.0.0.1` and opens a local page in
the user's browser. That page embeds the bridge URL — `https://<host>/?bridge=<capability>`,
no fragment — in `<iframe sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer">`
and hands it a `MessagePort`:

```js
iframe.contentWindow.postMessage({t: "tproxy-init", v: 1}, "https://<host>", [port]);
```

Over that port, both ways: `ArrayBuffer` = frames; page → host additionally
`{t:"status",state}`, `{t:"traffic",up,down}` (byte deltas for the tab's
counters) and `{t:"close"}`. Note the init name differs from the WebView one.

Consequences for the server: the bridge page must be framable from a
`http://127.0.0.1:<port>` origin, so do not send `X-Frame-Options` or a CSP
`frame-ancestors` that excludes it.

Do not authenticate the `Origin` header. A native WebView may omit it, and a
non-browser peer can forge any value, so it proves nothing either way — the
capability is what authenticates. Telegram's reference relay removed its own
origin check for exactly this reason.

The handshake timeout on this path is `kWelcomeTimeout` 30 s.

## 5. Frames

All traffic between client and server is a sequence of frames inside binary
WebSocket messages.

```
offset  size  field
0       1     type
1       3     stream id, big-endian, 24 bits
4       4     payload length, big-endian
8       N     payload
```

| Type | Value | Sender | Payload |
|---|---|---|---|
| `Open` | `0x01` | client | empty |
| `Data` | `0x02` | both | 1 … 1 MiB bytes |
| `Close` | `0x03` | both | empty |
| `Window` | `0x04` | both | 4 bytes, big-endian, non-zero |
| `Ping` | `0x05` | server | ≤ 64 bytes |
| `Pong` | `0x06` | client | echo of the Ping payload |
| `Hello` | `0x10` | client | one byte `0x01` (version) |
| `Welcome` | `0x11` | server | empty |
| `AuthChallenge` | `0x12` | — | reserved, never sent or accepted |
| `AuthResponse` | `0x13` | — | reserved, never sent or accepted |
| `Bye` | `0x1F` | both | empty |

Limits (`web_proxy_frame.h`, `web_proxy_transport.cpp`):

| Constant | Value |
|---|---|
| `kFrameHeaderSize` | 8 |
| `kMaxFramePayload` | 1 MiB |
| `kMaxBatchFrames` | 4096 frames per message |
| `kInitialStreamWindow` | 4 MiB |
| `kDataFrameSize` | 64 KiB (client's Data chunk) |
| `kWindowFlushBytes` / `kWindowFlushDelay` | 256 KiB / 20 ms (client's Window batching) |

A message may contain several frames back to back. It must contain at least one
frame and no trailing partial bytes (`processRelayPayload`). An unknown type, a
payload over 1 MiB, or more than 4096 frames in a message is a protocol error.

Stream id 0 is the control channel. Stream ids are allocated by the client as
`(counter % 0xFFFFFF) + 1`.

## 6. Session

1. Client sends `Hello` on stream 0 with payload `0x01`.
2. Server replies with `Welcome` on stream 0, **empty payload, alone in its
   message**, and nothing before it. A second `Welcome`, a `Welcome` with a
   payload, or any other frame before it is a protocol error.
3. From then on the server may send `Ping` (≤ 64 bytes), which the client
   answers with an identical `Pong`, and `Bye`, which the client treats as
   the end of the transport. The client never sends `Ping`.
4. Any other type on stream 0 — including `Hello`, `Pong`, `AuthChallenge`,
   `AuthResponse` — is a protocol error when received by the client.

A protocol error is not a soft failure: `Transport::Private::protocolError`
drops the whole transport and every stream in it.

## 7. Streams

- The client opens a stream with `Open` (empty payload). The server sends
  nothing in reply; the client treats the stream as connected immediately.
- `Open` carries **no destination**. The target data centre is inside the
  stream's first bytes (§8).
- `Data` must be non-empty. `Window` must be exactly 4 bytes and non-zero.
  `Close` must be empty. Either side may `Close`.
- Frames for a stream the client has recently closed (it remembers the last
  4096 ids) are tolerated if well-formed. Frames for an id that never existed
  are a protocol error.
- Per-stream buffers on the client: 8 MiB / 1024 pending chunks; exceeding
  them closes that stream.

### Flow control

Each direction of each stream starts with 4 MiB of credit. A sender may only
put bytes on the wire while it has credit, and each `Data` payload consumes
its length. The receiver returns credit with `Window` as it drains the data;
the amount is added to the sender's credit, saturating at 2³²−1.

The client sends `Data` in chunks of at most 64 KiB and grants `Window` in
batches (256 KiB or 20 ms), never more than 4 MiB outstanding. A server that
sends one byte more than its credit allows triggers a protocol error and loses
every stream in the session, so the only safe design is to reserve credit
before reading from the data centre.

## 8. Inside a stream

The bytes of a stream are exactly what the same client would write to a TCP
socket towards an MTProxy: `WebProxySocket` replaces the socket, nothing else
changes (`connection_tcp.cpp`).

The first 64 bytes are the obfuscated2 prefix:

```
[0:56]   random (constrained by isGoodStartNonce)
[8:40]   AES-256 key material, client → server
[40:56]  AES-CTR IV, client → server
[56:60]  transport tag: 0xEFEFEFEF abridged, 0xEEEEEEEE intermediate, 0xDDDDDDDD padded
[60:62]  data-centre id, int16 little-endian
[62:64]  random
```

Keys: `key = SHA256(material ‖ secret16)` where `secret16` is the 16-byte secret
(the `dd` byte stripped). The server → client direction uses bytes 8..56
reversed. The client encrypts the whole block with its send key and then
overwrites the first 56 bytes with plaintext, so only the tag and DC id travel
encrypted. A wrong secret shows up as an unknown tag — that is the server's
only authentication of the stream, exactly as in MTProxy.

DC id encoding (`SessionPrivate::getProtocolDcId`): magnitude is the DC
number, negative means the media cluster, `+10000` means the test servers.

From there on the server is an MTProxy: open an obfuscated2 connection to the
DC with the same tag and DC id (no secret), and re-encrypt the stream in both
directions.

## 8a. Carrying the frames over plain HTTP

Nothing in the client dictates how the bridge page reaches the server: the page
is served by the relay, so the page-to-server carrier is the server author's
choice. Telegram's reference server defines four (`https`, `https-lanes`,
`websocket`, `websocket-lanes`) and picks one per profile; this relay serves a
page that tries a WebSocket and falls back to plain HTTPS by itself.

The fallback used here, for anyone implementing the same page:

| Request | Headers | Meaning |
|---|---|---|
| `POST /` | `X-Tgwp-Session`, `X-Tgwp-Seq` | uplink batch, `204` on success |
| `GET /` | `X-Tgwp-Session`, `X-Tgwp-Cursor` | downlink, held up to 25 s; `200` with a batch, `204` if nothing happened |
| `DELETE /` | `X-Tgwp-Session` | end the session |

A batch is length-prefixed messages: a 4-byte big-endian length, then that many
bytes, repeated. The session token is minted by the relay and embedded in the
bridge page; it is the credential for these requests, so the capability is not
repeated in them.

Numbering is the point. An HTTP request can be retried by anything in the path,
and a batch applied twice would inject the same MTProto bytes twice. A repeat
of the previous sequence number is answered from the previous result, and a gap
is refused with `409` rather than guessed at.

## 9. What the server must look like from outside

The client checks nothing about the HTTP response except that the page loads
and behaves. The camouflage requirements therefore come from the threat model,
not from the client:

- Serve a real site on `/` and everywhere else.
- Serve the bridge only when `?bridge=` matches exactly, on `GET /`.
- Answer a wrong or missing capability **identically** to a request without
  one: same status, same headers, same body, same timing. No 403, no
  distinctive error, no second path.
- Answer a WebSocket upgrade without the capability the way a site without a
  WebSocket endpoint would.
- A stream whose obfuscated2 prefix does not decrypt is closed without
  explanation.

## 10. Checklist for implementers

- [ ] Normalise the domain like `NormalizeWebProxyHost`
- [ ] Capability: HMAC over `"tdesktop-web-proxy-bridge-v1\n" + host`, key includes `dd`
- [ ] Constant-time comparison; indistinguishable failure
- [ ] Bridge page: both carriers, `tproxy-android-init` with nonce, `tproxy-init` with port
- [ ] No `frame-ancestors` / `X-Frame-Options` that blocks `http://127.0.0.1:*`
- [ ] `Welcome` first, empty, alone
- [ ] Do not gate the WebSocket upgrade on `Origin`
- [ ] Never send `Open`, `Hello`, `Pong`, `AuthChallenge`, `AuthResponse`
- [ ] Never exceed the client's window; never send empty `Data`
- [ ] Decrypt the obfuscated2 prefix with the 16-byte secret; route by DC id
- [ ] Reject `ee` secrets at configuration time
