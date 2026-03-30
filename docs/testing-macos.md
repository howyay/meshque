# Testing meshque on macOS (ARM)

## Get the binary

**Option A — CI artifact:**
Download `meshque-macos-arm64` from the GitHub Actions build artifacts.

```bash
chmod +x meshque
```

**Option B — Build locally:**
```bash
git clone <repo-url> && cd meshque
cargo build -p meshque --release
cp target/release/meshque .
```

## Test

You need two machines on different networks (or one macOS + one Linux).
Both peers use the same network name and token. The signaling server is already live.

### macOS side

```bash
# Run meshque (needs root for TUN device)
sudo ./meshque up \
  --network cross-217246a4 \
  --token '<token>' \
  --signal-server https://meshque-signaling.haoye.workers.dev \
  -v
```

You'll see:
```
INFO meshque::nat: NAT discovery complete reflexive=<your-public-ip> nat_type="cone"
INFO meshque::mesh: Joined network 'cross-217246a4' ip=100.64.0.x peers=...
INFO meshque::mesh: Mesh active. Press Ctrl-C to stop.
```

Wait until the Linux side also runs the same command with the same network/token.

### After both peers connect

You should see:
```
INFO meshque::mesh: Connected to peer peer=100.64.0.x
```

### Verify tunnel

```bash
# From macOS (check the logs for your assigned 100.64.0.x)
ping 100.64.0.1   # ping the other peer
ping 100.64.0.2

# Check the TUN interface (default macOS name is utun9)
ifconfig utun9
```

### Troubleshooting

| Issue | Fix |
|---|---|
| `Operation not permitted` | Must run with `sudo` |
| `device name must start with utun` | Use `--tun-name utun9` or another `utun*` name |
| QUIC connection timeout | Both behind symmetric NAT — hole punch can't work |
| `utun9` doesn't appear | TUN creation failed — check macOS security settings |

### macOS TUN permissions

On macOS 13+, you may need to allow the unsigned binary in System Settings > Privacy & Security. Alternatively, sign it:

```bash
codesign --sign - meshque
sudo ./meshque up --network cross-217246a4 --token '<token>' --signal-server https://meshque-signaling.haoye.workers.dev -v
```
