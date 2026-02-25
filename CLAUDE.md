# CLAUDE.md — wyze-gwell-bridge

## What This Is

Streams Wyze GWell cameras (OG, etc.) to RTSP via pure Go P2P client + mediamtx. Three Docker services: `wyze-api` (Python auth), `wyze-p2p` (Go P2P), `mediamtx` (RTSP server).

## Architecture

```
docker-compose.yml orchestrates 3 services on macvlan + bridge networks:
  wyze-api  (Python) — Wyze auth, camera list, token management
  wyze-p2p  (Go)     — P2P connection, crypto, stream extraction → ffmpeg → RTSP
  mediamtx           — RTSP/HLS server
```

## Project Structure

```
wyze-gwell-bridge/
├── docker-compose.yml
├── .env.example / .env
├── .gitignore
├── README.md
├── CLAUDE.md                ← this file
├── data/                    ← persistent (manual_ips.json)
├── wyze-api/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py
└── wyze-p2p/
    ├── Dockerfile
    ├── go.mod               ← github.com/wlatic/wyze-gwell-bridge/wyze-p2p
    ├── IMPLEMENTATION_STATUS.md
    ├── cmd/gwell-proxy/main.go
    └── pkg/
        ├── gwell/           ← P2P protocol (session.go, mtp.go, certify.go, rc5.go, etc.)
        ├── stream/          ← H.264 extraction + ffmpeg RTSP publisher
        └── wyze/            ← Python API HTTP client
```

## Build & Run

```bash
docker compose build
docker compose up -d
```

## Run Tests

```bash
sudo docker run --rm -v $(pwd)/wyze-p2p:/src -w /src golang:1.21-alpine go test ./pkg/gwell/ -v
```

## Team Structure

Standard team for working on this project:

- **researcher** (`subagent_type: Explore`) — codebase exploration, SDK decompilation analysis (Ghidra), protocol investigation, reading logs
- **implementer** (`subagent_type: general-purpose`, `isolation: worktree`) — Go code changes, new features, bug fixes, refactoring
- **builder** (`subagent_type: general-purpose`, `isolation: worktree`) — Docker builds, deployment to remote host (10.10.21.1), running tests, collecting logs for validation

For research-only sessions (no code changes), only spawn `researcher`.
For quick fixes, `implementer` alone may suffice (still confirm with user).

## Key Details

- **Module path**: `github.com/wlatic/wyze-gwell-bridge/wyze-p2p`
- **Networking**: macvlan (external, `directlan`) + bridge (internal service-to-service)
- **Camera IPs**: Set manually via `/Camera/SetManualIP`, persisted in `data/manual_ips.json`
- **Multi-camera**: Device discovery runs once, 15s stagger between camera starts
- **Protocol**: Full GWell/IoTVideo P2P — see `wyze-p2p/IMPLEMENTATION_STATUS.md` for details
