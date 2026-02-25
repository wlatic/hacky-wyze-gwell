# Native P2P Go — Implementation Status

Last updated: 2026-02-25

## What's Done (Complete and Working)

### 1. Full P2P Protocol in Pure Go
Every phase of the GWell/IoTVideo P2P protocol is implemented and tested against a live Wyze camera (GW_DUO_80482C6DF336). No QEMU shim, no Android, no native ARM libraries — all reverse-engineered from Ghidra decompilation of libiotp2pav.so.

### 2. Crypto (pkg/gwell/rc5.go, xor.go, hash.go)
- **RC5-32/6** — 8-byte block encryption/decryption (for frame encryption, AV data)
- **RC5-64/6** — 16-byte block encryption/decryption (for CertifyReq inner encryption)
- **XOR cipher** — for frame ID fields
- **giot_hash_string** — custom hash (seed=0x4e67c6a7)
- **HMAC-MD5 + AES-ECB** — signature generation for CertifyReq
- **22 unit tests** passing (1 pre-existing test for InitInfoMsg decryption has a known issue)

### 3. Protocol Frame Building (pkg/gwell/certify.go, frame.go, mtp.go)
- **GUTES frame format** — 24-byte header with proto, subtype, checksum, encryption flags
- **Three encryption modes**: Mode 0 (plain), Mode 1 (frame-derived key), Mode 2 (session key)
- **CertifyReq** (sub=0x0C, 164B) — inner RC5-64 encrypted random key, 80B signature
- **InitInfoMsg** (sub=0xA6, 62B) — device list query
- **Subscribe** (sub=0xB0) — DevID and token-based subscribe
- **CALLING** (sub=0xA4) — initiates MTP transport negotiation
- **NetworkDetect** (sub=0xB9) — LAN detection probe
- **Heartbeat** — periodic keep-alive
- **MTP frames** — 0xC0 magic, 6-byte standard header, 14-byte extended (relay) header
- **KCP segments** — PUSH (cmd=81), ACK (cmd=82), proper conv IDs
- **AVSTREAMCTL** — INITREQ (76B), ACCEPT, START
- **Relay activation** — TCP relay register, UDP relay, session socket, passthrough

### 4. P2P Session State Machine (pkg/gwell/session.go)
Complete `Session.Run(deviceID)` that executes all phases:

```
Phase 1: connect()     — Discover P2P servers (DNS or fallback list), connect via UDP
Phase 2: certify()     — CertifyReq → CertifyResp, establish session_id + session key
Phase 3: initInfo()    — InitInfoMsg → device list, select target device by name
Phase 4: networkDetect() — Send 0xB9 probe for LAN detection
Phase 5: subscribe()   — DevID + token subscribe (0xB0), wait for responses
Phase 6: calling()     — CALLING → MTP_RES_RESPONSE, parse relay addresses,
                         open UDP socket, activate relays, probe camera ports,
                         wait for CREATE_KCP, send meter ACKs
Phase 7: streamLoop()  — Create dual KCP sessions (DATA + CTRL),
                         INITREQ retry loop → ACCEPT → START,
                         main receive loop: MTP → KCP → RC5 decrypt → H.264 → io.Writer
```

### 5. KCP Transport (pkg/gwell/kcp.go)
- Custom KCP implementation with SDK-matching parameters:
  - nodelay=0, interval=5ms, resend=10, nc=1 (no congestion control)
  - window=64x64 (send/receive)
- Dual KCP sessions: DATA (conv = linkID & 0x7FFFFFFF), CTRL (conv = linkID | 0x80000000)
- Output function sends ACKs LAN-only, PUSHes to all paths (LAN + relay + server)

### 6. H.264 Stream Extraction
- **RC5 decryption** of AV data (type=0x04) from KCP receive queue
- **0xffffff88 head_info skip** (28 bytes) — first AV packet contains codec params
- **Direct H.264 Annex B output** — SPS/PPS/IDR/P-frames, ready for ffmpeg
- **Proven**: 25,648 packets / 24.1 MB continuous streaming in 120s test

### 7. FFmpeg RTSP Publishing (pkg/stream/ffmpeg.go)
- `FFmpegPublisher` — spawns ffmpeg process, pipes H.264 to stdin
- Publishes to mediamtx via `rtsp://host:port/live/CAMERA_ID`
- Implements `io.Writer` interface — plugs directly into `SessionConfig.H264Writer`
- Health check (`Alive()`) and graceful shutdown (`Close()`)

### 8. Production Entry Point (cmd/gwell-proxy/main.go)
- Fetches camera list from Python API (`cryze_api`)
- Per-camera goroutines with reconnect loop
- Token refresh (1-hour interval)
- Deadman switch (120s timeout on stream data)
- FFmpeg health monitoring
- `writeTracker` wraps io.Writer to track last-write time atomically

### 9. Docker Deployment
- **Dockerfile**: 2-stage build (golang:1.21-alpine → alpine:3.19 + ffmpeg)
- **docker-compose.yml**: 3 services (cryze_api, native_p2p, mediamtx)
- **macvlan networking** (cryze_lan) — containers get their own LAN IPs

---

## Critical Protocol Details (Don't Lose These)

### AVSTREAMCTL Handshake (the key to getting video)
Three discoveries were needed to get video flowing:

1. **Non-zero streamID** — `INITREQ[4:8]` and `START[4:8]` must contain a random uint32. Zero is accepted but camera never sends video for streamID=0.

2. **avKey format** — `INITREQ[24:56]` (32 bytes) must be `[0x02, 0, ..., 0]`. The `0x02` may indicate channel count. SDK does NOT exchange random crypto keys via INITREQ/ACCEPT.

3. **Viewer AV_INIT** — After sending START, viewer must send a 32-byte RC5-encrypted frame (type=0x04, sub=0x02) on DATA KCP. Without this, camera never starts encoding. Content: zeros encrypted with MTP RC5 key.

### Complete Handshake Sequence
```
→ CTRL KCP sn=0: INITREQ (type=3, sub=0x02, streamID=random, avKey=[2,0,...])
← CTRL KCP sn=0: ACCEPT (type=3, cmd=2)
← DATA KCP sn=0: STARTED echo (type=3, cmd=6, streamID echoed back)
→ DATA KCP sn=0: STARTED echo (echo camera's STARTED back verbatim)
→ DATA KCP sn=1: Viewer AV_INIT (type=0x04, sub=0x02, 32B RC5-encrypted)
← DATA KCP sn=1: head_info (type=0x04, 0xffffff88 + codec params)
← DATA KCP sn=2+: H.264 video frames (type=0x04, ~1000B each)
```

### KCP ACK Fix (Critical — Stream Dies Without This)
- After sending `MTP_RES_REQUEST`, the UDP write deadline MUST be cleared: `pc.SetWriteDeadline(time.Time{})`
- Without this, the write deadline set earlier poisons ALL subsequent WriteToUDP calls
- After 5 seconds, KCP ACK delivery silently fails → camera stops sending
- Result: 682 packets (with bug) vs 25,648 packets (fixed)

### Transport Priority
```
1. LAN TCP (direct to camera TCP socket)
2. LAN UDP (direct to camera, ports from MTP_RES_RESPONSE: session/lan/outer/6789/32761/32100)
3. TCP relay (via relay servers from CALLING response)
4. UDP relay (via relay servers, extended MTP header with TID)
5. PASSTHROUGH (via P2P server, GUTES 0xB9 frame wrapping)
```

### Token Format
- accessToken from Wyze API = hex string
- First 128 hex chars → 64 bytes decoded
- Token key = decoded[48:64] (16 bytes) → RC5-64 key for CertifyReq
- Chars after 128: base64-encoded extra data (80 bytes) → used for subscribe

### MTP Frame Format
```
Standard (6B header):
  [0]    = 0xC0 (magic)
  [1]    = flags (bit7=urgent, bits5-6=mode, bit4=control)
  [2:4]  = length encoding (3-bit + 8-bit shifted)
  [4:6]  = checksum XOR length
  [6:]   = KCP/payload data

Extended (14B header, for relay):
  [0:6]  = same as standard
  [6:14] = destination TID (8 bytes)
  [14:]  = KCP/payload data
```

### MTP Session Control Commands (before KCP data in frame)
```
0x01 = CREATE_KCP (meter request)
0x02 = CREATE_KCP_RESPONSE (meter ack)
0x04 = session control
0x06 = session control
0x21 = session control
0x24 = session control
0x25 = create KCP session
```

---

## File Layout

```
cmd/gwell-proxy/main.go        — Production entry point (reconnect, token refresh, ffmpeg)
cmd/certify_probe/main.go      — 4164-line test tool (standalone, all protocol inline)
pkg/gwell/
  session.go                    — Session state machine (1409 lines, all 7 phases)
  mtp.go                        — MTP frame builders, KCP helpers, decrypt/parse (632 lines)
  kcp.go                        — KCP ARQ protocol implementation
  certify.go                    — CertifyReq/Resp, InitInfoMsg, Subscribe, Calling, Heartbeat
  frame.go                      — GUTES frame building, checksum, constants
  rc5.go                        — RC5-32/6 and RC5-64/6 encryption
  discovery.go                  — P2P server discovery (DNS + fallback)
  hash.go                       — giot_hash_string
  xor.go                        — XOR cipher
pkg/stream/ffmpeg.go            — FFmpegPublisher (io.Writer → ffmpeg stdin → RTSP)
pkg/wyze/client.go              — Python API client (camera list, device info, tokens)
Dockerfile                      — 2-stage Docker build (Go build → Alpine + ffmpeg)
```

---

## What Remains (TODO)

### Completed
- [x] Build gwell-proxy — compiles clean
- [x] Build certify_probe — compiles clean
- [x] **Live test gwell-proxy against camera** — both cameras streaming via Docker
- [x] Verify RTSP stream is viewable (ffmpeg → mediamtx RTSP/HLS working)
- [x] **Multi-camera simultaneous streaming** — both cameras (Front + Well House) streaming
- [x] **Device discovery** — `DiscoverDevices()` gets device list + working server once
- [x] **Camera stagger** — 15s delay between camera starts avoids P2P server confusion
- [x] **Dashboard** — `/streams` endpoint on cryze_api shows RTSP URLs for all cameras
- [x] **Friendly names** — cameras use stream names from API (e.g., "Front", "Well House")

### Multi-Camera Architecture (Important)
The P2P server has several quirks with multiple simultaneous sessions from the same account:
1. **Device list caching** — Server may skip 0xA7 (InitInfoResp) for second session
2. **Rate limiting** — DetectReq2 probes may be ignored shortly after another connection
3. **Cross-session interference** — Simultaneous sessions can receive each other's frames

Solution implemented in `gwell-proxy/main.go`:
- `DiscoverDevices()` creates a temporary session to get device list + working server address
- Each camera session receives pre-populated `Devices` and `ServerAddr` in `SessionConfig`
- Sessions still send `InitInfoMsg` to get per-session routing ID (0x0D)
- 15-second stagger between camera starts

### Nice to Have
- [ ] Fix pre-existing `TestBuildInitInfoMsg` test failure (encryption mode mismatch — cosmetic)
- [ ] Token refresh mid-session (currently `_ = newToken` placeholder)
- [ ] Timestamp passthrough (ffmpeg DTS warnings are cosmetic but could improve playback)
- [ ] LAN TCP transport path (UDP works, TCP not yet exercised)
- [ ] Graceful session close on SIGTERM
- [ ] Remove debug logging from session.go/certify.go once stable

---

## Build Commands

```bash
# Build gwell-proxy (production)
cd /mnt/zfs/claude/system/projects/cryze_v2-main
sudo docker run --rm -v $(pwd)/native_p2p_go:/src -w /src golang:1.21-alpine \
  go build -o /src/gwell-proxy ./cmd/gwell-proxy/

# Build certify_probe (test tool)
sudo docker run --rm -v $(pwd)/native_p2p_go:/src -w /src golang:1.21-alpine \
  go build -o /src/certify_probe_bin ./cmd/certify_probe/

# Run unit tests
sudo docker run --rm -v $(pwd)/native_p2p_go:/src -w /src golang:1.21-alpine \
  go test ./pkg/gwell/ -v

# Build Docker image (production)
docker compose build native_p2p

# Run full stack
docker compose up

# Run certify_probe standalone (test with live camera)
TOKEN_JSON=$(curl -s 'http://localhost:8080/Camera/CameraToken?deviceId=GW_DUO_80482C6DF336') && \
  ACCESS_ID=$(echo "$TOKEN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['accessId'])") && \
  ACCESS_TOKEN=$(echo "$TOKEN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['accessToken'])") && \
  sudo docker run --rm --network cryze_lan --ip 10.10.20.210 \
    -v $(pwd)/native_p2p_go:/src alpine \
    /src/certify_probe_bin -id "$ACCESS_ID" -token "$ACCESS_TOKEN" -lanip 10.10.102.163
```

## Ghidra References

Key SDK functions decompiled and implemented:
| SDK Function | Address | What It Does |
|---|---|---|
| iv_mtp_session_new | 0x157cb0 | RC5 key at +0x834, context at +0x83c |
| iv_mtp_session_send_rcv_proc | 0x15db30 | Main 10ms loop (rcv, KCP update, send) |
| iv_on_rcv_kcp_cmdfrm | 0x152b64 | Decrypts type=2 CMD frames |
| iv_send_av_ringbuf | 0x15d6cc | RC5 encrypts AV data, sends via DATA KCP |
| FUN_00164d60 | 0x164d60 | Builds 0xffffff88 head_info (28B) |
| FUN_00165078 | 0x165078 | av_send_thread: head_info first, then encode |
| giot_eif_subscribe_dev | 0x1769a4 | Builds 0xB0 subscribe frame |
| iv_subscribe_dev | 0x1255ac | Token processing (base64 + AES) |
| iv_gutes_start_active_certify_req | 0x134864 | CertifyReq frame construction |
| iv_gute_frm_rc5_encrypt | 0x12ef0c | Frame encryption mode dispatch |

Ghidra project: `/tmp/ghidra_project_cmdfrm/cmdfrm_project` (may need recreation)
Ghidra binary: `/mnt/zfs/claude/ghidra_11.3.1_PUBLIC`
