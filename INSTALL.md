# Installation Guide - LGVIEW-NG

This guide outlines how to build and install **lgview-ng** from source.

## Pre-compiled Binaries

If you are on Linux x86_64, you can skip compiling from source and download pre-compiled release binaries directly from the **Versões (Releases)** page on [Codeberg](https://codeberg.org/gondim/lgview-ng/releases).

## Prerequisites

To build and run `lgview-ng`, you must have Rust and Cargo installed on your system.

### Installing Rust and Cargo

If you don't have Rust installed, you can install it using `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen instructions to complete the installation. Once finished, configure your shell:

```bash
source $HOME/.cargo/env
```

To verify the installation, run:

```bash
cargo --version
```

---

## Building from Source

1. Clone the repository (or navigate to your local directory):
   ```bash
   git clone https://github.com/gondimcodes/lgview-ng.git
   cd lgview-ng
   ```

2. Compile the application in release mode:
   ```bash
   cargo build --release
   ```
   The compiled executable will be generated at `./target/release/lgview-ng`.

---

## Installing Globally

To install the binary on your system so that it's accessible anywhere:

### Option 1: Cargo Install (Recommended)
You can compile and install directly into your Cargo binary directory (`~/.cargo/bin`):
```bash
cargo install --path .
```
Ensure `~/.cargo/bin` is in your system `PATH` (typically configured automatically by rustup).

### Option 2: Manual Copy
Copy the compiled binary into a directory in your `$PATH`, for example:
```bash
sudo cp target/release/lgview-ng /usr/local/bin/
```

Verify that it is working correctly:
```bash
lgview-ng --help
```
