# LGVIEW-NG

[![License](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)

**lgview-ng** is a high-performance Rust tool designed to verify BGP routing advertisements and detect prefix leaks in DDoS mitigation environments in real-time.

When an IPv4 `/24` or IPv6 `/48` prefix is placed under DDoS mitigation, it must be announced with a specific AS-PATH sequence ending in:
$$\text{AS-PATH: } [\dots \text{any transit AS} \dots] \rightarrow \mathbf{ASN_{mitigation}} \rightarrow \mathbf{ASN_{mitigated}}$$

Any path that announces the prefix but does not flow through the DDoS scrubbing provider (e.g. bypassing the mitigation ASN) is flagged as an **anomalous path or prefix leak**.

---

## Features

- **Real-Time Direct Verification**: The tool initiates concurrent, asynchronous TCP Telnet sessions directly to BGP Looking Glasses (Route Servers) to parse current active routing tables.
- **Dynamic Configuration**: Looking Glass target servers, connection types, and parameters are defined in an external `config.toml` file, making it easy to add or remove servers without recompiling.
- **Dynamic Alignment**: Terminal table layout is calculated dynamically to format and align long IPv6 collector addresses and AS-paths cleanly.
- **CLI Automation**: Returns exit code `1` when leaks are detected, enabling integration with CI/CD pipelines, cron jobs, and alerting systems.
- **Rich Visual Output**: Features colorized output (green for valid paths, red for anomalous leaks) and a custom startup banner.

---

## Configuration (`config.toml`)

Servers are defined dynamically in a local TOML file. For example:

```toml
[[looking_glasses]]
name = "Route Views"
host = "route-views.routeviews.org"
is_route_views = true

[[looking_glasses]]
name = "IX.br São Paulo"
host = "lg.sp.ptt.br"
is_route_views = false
```

- `name`: Display name used in report tables.
- `host`: Hostname or IP address of the Looking Glass.
- `is_route_views`: Flag indicating if the target is Route Views (which requires sending `rviews` as the initial username).

---

## Parameters

The tool requires three mandatory arguments:

| Argument | Description |
| :--- | :--- |
| `--prefix` | The IPv4 `/24` or IPv6 `/48` subnet under mitigation |
| `--asn-mitigation` | The ASN of the DDoS mitigation provider (e.g., `264409` for Huge Networks) |
| `--asn-mitigated` | The owner ASN of the prefix (e.g., your network ASN `65001`) |
| `--config` | (Optional) Path to the configuration TOML file. Defaults to `config.toml` |

---

## Usage

### Run directly with Cargo
```bash
cargo run -- \
  --prefix 177.11.98.0/24 \
  --asn-mitigation 263009 \
  --asn-mitigated 262875
```

### Run the installed binary
```bash
lgview-ng \
  --prefix 209.61.8.0/24 \
  --asn-mitigation 53427 \
  --asn-mitigated 53158 \
  --config /path/to/config.toml
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
Version: 1.2.0

Checking prefix: 209.61.8.0/24
Expected ending path: 53427 53158

Loading configuration from: config.toml
Initiating concurrent Looking Glass checks on 4 servers...

Looking Glass             | Status               | AS-PATH
--------------------------------------------------------------------------------------
Route Views               | VALID                | 3257 53427 53158
IX.br São Paulo           | VALID                | 53427 53158
IX.br Rio de Janeiro      | NO PATHS             | No announcements containing target mitigated ASN found
IX.br Fortaleza           | NO PATHS             | No announcements containing target mitigated ASN found

Summary Report:
Total checked paths: 2
Valid paths        : 2
Anomalous / Leaks  : 0

SUCCESS: All paths are correctly routed via the mitigation provider!
```

---

## Installation

See [INSTALL.md](INSTALL.md) for full instructions on building and installing `lgview-ng`.

## Support

Visit [ISP Focus](https://ispfocus.net.br) for network consulting and consulting resources.
