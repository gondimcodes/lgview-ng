# LGVIEW-NG

[![License](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)

**lgview-ng** is a high-performance Rust tool designed to verify BGP routing advertisements and detect prefix leaks in DDoS mitigation environments.

When an IPv4 `/24` or IPv6 `/48` prefix is placed under DDoS mitigation, it must be announced with a specific AS-PATH sequence ending in:
$$\text{AS-PATH: } [\dots \text{any transit AS} \dots] \rightarrow \mathbf{ASN_{mitigation}} \rightarrow \mathbf{ASN_{mitigated}}$$

Any path that announces the prefix but does not flow through the DDoS scrubbing provider (e.g. bypassing the mitigation ASN) is flagged as an **anomalous path or prefix leak**.

---

## Features

- **Global High-Precision Verification**: Instead of querying a static list of Looking Glasses (which can be slow, unreliable, or require credentials), `lgview-ng` queries the **RIPE NCC Routing Information Service (RIS) API**. 
  It uses a **hybrid verification model**:
  1. It fetches the BGP baseline state (the most recent full RIB dump) for global coverage.
  2. It queries all BGP updates since that dump up to the current second to apply real-time announcements (`A`) and withdrawals (`W`).
  This achieves real-time precision without missing inactive but stable announcements.
- **Dynamic Alignment**: Terminal table layout is calculated dynamically to format and align long IPv6 collector addresses and AS-paths cleanly.
- **CLI Automation**: Returns exit code `1` when leaks are detected, enabling integration with CI/CD pipelines, cron jobs, and alerting systems.
- **Rich Visual Output**: Features colorized output (green for valid paths, red for anomalous leaks) and a custom startup banner.

---

## Data Source

The tool fetches real-time BGP routing state and updates from the RIPEstat APIs:
- `https://stat.ripe.net/data/bgp-state/data.json`
- `https://stat.ripe.net/data/bgp-updates/data.json`

This ensures that we observe the prefix advertisements from multiple independent BGP peers worldwide simultaneously.


---

## Parameters

The tool requires three mandatory arguments:

| Argument | Description |
| :--- | :--- |
| `--prefix` | The IPv4 `/24` or IPv6 `/48` subnet under mitigation |
| `--asn-mitigation` | The ASN of the DDoS mitigation provider (e.g., `264409` for Huge Networks) |
| `--asn-mitigated` | The owner ASN of the prefix (e.g., your network ASN `65001`) |

---

## Usage

### Run directly with Cargo
```bash
cargo run -- \
  --prefix 192.168.0.0/24 \
  --asn-mitigation 264409 \
  --asn-mitigated 65001
```

### Run the installed binary
```bash
lgview-ng \
  --prefix 2001:db8::/48 \
  --asn-mitigation 264409 \
  --asn-mitigated 65001
```

### Sample Output

```text
$$\       $$$$$$\  $$\    $$\ $$$$$$\ $$$$$$$$\ $$\      $$\         $$\   $$\  $$$$$$\  
$$ |     $$  __$$\ $$ |   $$ |\_$$  _|$$  _____|$$ | $\  $$ |        $$$\  $$ |$$  __$$\ 
$$ |     $$ /  \__|$$ |   $$ |  $$ |  $$ |      $$ |$$$\ $$ |        $$$$\ $$ |$$ /  \__|
$$ |     $$ |$$$$\ \$$\  $$  |  $$ |  $$$$$\    $$ $$ $$\$$ |$$$$$$\ $$ $$\$$ |$$ |$$$$\ 
$$ |     $$ |\_$$ | \$$\$$  /   $$ |  $$  __|   $$$$  _$$$$ |\______|$$ \$$$$ |$$ |\_$$ |
$$ |     $$ |  $$ |  \$$$  /    $$ |  $$ |      $$$  / \$$$ |        $$ |\$$$ |$$ |  $$ |
$$$$$$$$\\$$$$$$  |   \$  /   $$$$$$\ $$$$$$$$\ $$  /   \$$ |        $$ | \$$ |\$$$$$$  |
\________|\______/     \_/    \______|\________|\__/     \__|        \__|  \__| \______/ 
https://ispfocus.net.br
Version: 1.1.0

Checking prefix: 193.0.0.0/21
Expected ending path: 1273 3333

Source ID (RRC)           | Status               | AS-PATH
--------------------------------------------------------------------------------
00-165.16.221.66          | VALID                | 37721 37468 1273 3333
00-193.0.0.56             | VALID                | 3333 37468 1273 3333
00-2001:1890:111d:1::63   | LEAK / ANOMALOUS     | 7018 3356 263009 3333

Summary Report:
Total checked paths: 3
Valid paths        : 2
Anomalous / Leaks  : 1

WARNING: Prefix leaks detected!
```

---

## Installation

See [INSTALL.md](INSTALL.md) for full instructions on building and installing `lgview-ng`.

## Support

Visit [ISP Focus](https://ispfocus.net.br) for network consulting and consulting resources.
