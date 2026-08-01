# Technology Stack & Architecture — lgview-ng

This document provides a detailed technical overview of the technologies, libraries, network protocols, and CI/CD automation powering **lgview-ng** (v1.5.2).

---

## 1. Core Language & Runtime

* **Language**: **Rust (2024 Edition)**
  * **Rationale**: High-performance, memory-safe execution without garbage collection latency for concurrent BGP route queries across multiple Looking Glass servers.
* **Async Runtime**: [`tokio 1.35`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L13) (`features = ["full"]`)
  * **Usage**: Non-blocking concurrent TCP Telnet and HTTP sessions to query multiple Looking Glass nodes simultaneously.

---

## 2. Network Protocols & Telnet Engine

* **Telnet Connection Handling**: [`telnet 0.2`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L14)
  * **Usage**: Automated interactive Telnet sessions to public Looking Glass servers (e.g., Bird, Quagga, Cisco, Juniper CLI interfaces) to issue `show route` / `show bgp` commands.
* **HTTP Client**: [`reqwest 0.12`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L20) (`features = ["json"]`)
  * **Usage**: Asynchronous HTTP requests to fetch external Looking Glass APIs or web-based BGP lookup endpoints.
* **Async Utilities**: [`futures-util 0.3`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L19)
  * **Usage**: Stream handling and asynchronous future combinators for parallel server queries.

---

## 3. CLI Framework & Output Styling

* **CLI Argument Parser**: [`clap 4.4`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L12) (`features = ["derive"]`)
  * **Usage**: Command line interface parsing for target IP/prefix inputs, custom Looking Glass configurations, and filtering flags.
* **Terminal Coloring**: [`colored 2.1`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L16)
  * **Usage**: Visual status highlighting (green for protected routes, yellow/red for detected BGP prefix leaks or missing announcements).

---

## 4. Serialization & Configuration

* **TOML Configuration**: [`toml 0.8`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L18) and [`serde 1.0`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L17)
  * **Usage**: Parsing custom Looking Glass server definitions and credentials from `config.toml`.
* **JSON Processing**: [`serde_json 1.0`](file:///home/gondim/projetos/lgview-ng/Cargo.toml#L15)
  * **Usage**: Deserializing JSON responses from API-based Looking Glass servers.

---

## 5. Multi-Platform CI/CD Infrastructure & Code Mirroring

* **GitHub Actions Workflows**:
  * **Continuous Integration (`ci.yml`)**: Automated testing (`cargo test`) and static code checks across Linux and macOS environments.
  * **Continuous Delivery (`release.yml`)**: Automated multi-target builds on tag pushes.
* **Codeberg Pipeline (`.woodpecker.yml`)**:
  * **Woodpecker CI**: Automated testing (`cargo test`) and standalone Linux release packaging (`lgview-ng-<tag>-x86_64-unknown-linux-gnu.tar.gz`) published directly to Codeberg Releases via `woodpeckerci/plugin-release`.
