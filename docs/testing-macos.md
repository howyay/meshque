# Testing meshque on macOS (ARM)

## Get the binary

**Option A — CI artifact:**
Download `meshque-macos-arm64` from the GitHub Actions build artifacts.

```bash
chmod +x meshque
```

**Option B — Build locally:**
```bash
git clone <repo-url> && cd ipowt
cargo build -p meshque --release
cp target/release/meshque .
```

## Test

You need two machines on different networks (or one macOS + one Linux).
Both peers use the same room code. The signaling server is already live.

### macOS side

```bash
# Run meshque (needs root for TUN device)
sudo ./meshque connect test-room-xyz -v
```

You'll see:
```
INFO meshque::nat: NAT discovery complete reflexive=<your-public-ip> nat_type="cone"
INFO meshque::signaling: Joined room role="responder"
INFO meshque::signaling: Waiting for peer to join...
```

Wait until the Linux side also runs the same command.

### After both peers connect

You should see:
```
INFO meshque::connection: QUIC connection established
INFO meshque::connection: CONNECT-IP session established
INFO meshque::connection: Sent ADDRESS_ASSIGN / Received ADDRESS_ASSIGN
INFO meshque::tunnel: Tunnel active — forwarding packets
```

### Verify tunnel

```bash
# From macOS (you'll be either 100.64.0.1 or 100.64.0.2 — check the logs)
ping 100.64.0.1   # ping the other peer
ping 100.64.0.2

# Check the TUN interface
ifconfig meshque0
```

### Troubleshooting

| Issue | Fix |
|---|---|
| `Operation not permitted` | Must run with `sudo` |
| `Waiting for peer...` hangs | Other peer hasn't run the command yet — use same room code |
| QUIC connection timeout | Both behind symmetric NAT — hole punch can't work |
| `meshque0` doesn't appear | TUN creation failed — check macOS security settings |

### macOS TUN permissions

On macOS 13+, you may need to allow the unsigned binary in System Settings > Privacy & Security. Alternatively, sign it:

```bash
codesign --sign - meshque
sudo ./meshque connect test-room-xyz -v
```
