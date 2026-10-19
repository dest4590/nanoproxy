<div align=center>
  <img src="assets/logo.svg" alt="nanoproxy logo" width="200" />
  <h1>nanoproxy</h1>
  <h2>Ultra-lightweight dual HTTP & SOCKS5 proxy server</h2>
</div>

Designed for embedded routers (OpenWrt, Padavan, Xiaomi) and microservers where binary size and memory usage matter.

## Features

- **Two protocols on one port**: auto-detects SOCKS5 or HTTP/HTTPS CONNECT by the first handshake byte.
- **SOCKS5 (RFC 1928)**:
  - No-auth (`0x00`) or username/password auth (`0x02`, RFC 1929).
  - IPv4 (`0x01`), Domain Name (`0x03`), and IPv6 (`0x04`) address types.
- **HTTP / HTTPS Proxy (RFC 7230 / RFC 7235)**:
  - HTTPS tunneling via `CONNECT` (`HTTP/1.1 200 Connection Established`).
  - Plain HTTP proxy (GET, POST, etc.) with automatic stripping of hop-by-hop headers (`Proxy-Authorization`, `Proxy-Connection`).
  - Basic auth (`Proxy-Authorization: Basic <base64>`) with `407 Proxy Authentication Required` on failure.
  - Chunked header read with zero syscall overhead on large payloads.
- **Extremely lightweight**:
  - Static binary: **~70 KB** (nightly + UPX-packed via `build.sh`).
  - Worker thread stack limited to **64 KB**, zero heap overhead per connection.
  - Zero external dependencies — pure `std`.
- **Comprehensive test suite**: 43 unit and integration tests covering all protocols, auth schemes, and edge cases.

## Usage

```bash
# No auth, default port 1080
./nanoproxy

# With username/password authentication
./nanoproxy -b 0.0.0.0:1080 -a user:secret123

# Specific bind address and custom timeout (seconds)
./nanoproxy -b 100.64.0.11:1080 -a user:secret123 -t 30
```

### Options

| Flag | Long        | Description                   | Default        |
| ---- | ----------- | ----------------------------- | -------------- |
| `-b` | `--bind`    | Bind address                  | `0.0.0.0:1080` |
| `-a` | `--auth`    | `USER:PASS` credentials       | (none)         |
| `-t` | `--timeout` | Connection timeout in seconds | `15`           |
| `-h` | `--help`    | Print help                    |                |

## Real Verification Tests

Start the proxy server in test mode:

```bash
./nanoproxy -b 127.0.0.1:1088 -a admin:secret123 -t 10
# Output: listening on 127.0.0.1:1088
```

### 1. SOCKS5 with Auth (RFC 1928 / RFC 1929)

```bash
curl -s -i --socks5 127.0.0.1:1088 --proxy-user admin:secret123 https://httpbin.org/ip
```

**Output:**

```http
HTTP/2 200
date: Mon, 19 Oct 2026 09:08:09 GMT
content-type: application/json
content-length: 32

{
  "origin": "100.100.100.100"
}
```

Wrong credentials:

```bash
curl -s --socks5 127.0.0.1:1088 --proxy-user admin:wrongpass https://httpbin.org/ip
# Exit code: 97 (CURLE_PROXY_AUTH_FAIL)
```

### 2. HTTPS Tunneling via HTTP CONNECT (RFC 7231)

```bash
curl -s -i -x http://admin:secret123@127.0.0.1:1088 https://httpbin.org/ip
```

**Output:**

```http
HTTP/1.1 200 Connection Established

HTTP/2 200
date: Mon, 19 Oct 2026 09:08:23 GMT
content-type: application/json
content-length: 32

{
  "origin": "100.100.100.100"
}
```

Missing or invalid credentials return `407`:

```bash
curl -s -i -x http://127.0.0.1:1088 https://httpbin.org/ip
```

**Output:**

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="nanoproxy"
Content-Length: 0
Connection: close
```

### 3. Plain HTTP Proxy & Header Stripping (RFC 7230 / RFC 7235)

```bash
curl -s -i -x http://admin:secret123@127.0.0.1:1088 http://httpbin.org/get
```

**Output:**

```http
HTTP/1.1 200 OK
Date: Mon, 19 Oct 2026 09:08:36 GMT
Content-Type: application/json
Content-Length: 254
Connection: keep-alive

{
  "headers": {
    "Host": "httpbin.org",
    "User-Agent": "curl/8.18.0"
  }
}
```

_(Notice `Proxy-Authorization` is stripped before forwarding to upstream)._

### 4. Running the Built-in Test Suite

```bash
cargo test
# running 43 tests
# test auth::tests::test_verify_basic_correct ... ok
# test http::tests::test_http_connect_tunnel_no_auth ... ok
# test http::tests::test_hop_by_hop_headers_stripped ... ok
# test socks5::tests::test_socks5_ipv6_connect ... ok
# ...
# test result: ok. 43 passed; 0 failed; finished in 0.00s
```

## Building

### Native (current system)

```bash
cargo build --release
# Binary: target/release/nanoproxy
```

### Optimized Build (nightly + UPX, smallest binary)

`build.sh` runs the full size-reduction pipeline:

- Builds with nightly Rust and the following flags:
  - `-Z build-std=std,panic_abort` — rebuilds `std` from source, linking only `panic_abort` (no unwinder).
  - `-C panic=immediate-abort` — **fully disables** the panic handler
  - `-Z location-detail=none` — removes file/line metadata from panic location structs.
  - `--remap-path-prefix` — strips `$HOME/.cargo`, `$HOME/.rustup`, and project paths from the binary.
  - `-Wl,--gc-sections -Wl,--strip-all` — linker dead-section elimination and full symbol strip.
- Packs with `upx --best --lzma`.

**Requirements:** `rustup` with nightly toolchain + `rust-src` component, `upx`.

```bash
# Install requirements (once)
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Build
./build.sh
# Default target: x86_64-unknown-linux-musl
# Binary: target/x86_64-unknown-linux-musl/release/nanoproxy (~70 KB)
```

### Cross-Compilation for Router Architectures

Consumer routers and embedded boards run diverse CPU architectures, often without hardware floating point units (FPUs) or standard glibc runtime. Below are configurations for common router targets.

All targets can be linked statically using `.cargo/config.toml` and compressed with `./build.sh <target>`.

#### Architecture Matrix

| Target Triple | CPU Architecture | Common Devices / Platforms | Toolchain / Linker |
| ------------- | ---------------- | -------------------------- | ------------------ |
| `armv7-unknown-linux-musleabi` | ARMv7 (32-bit Soft-Float) | Xiaomi BE5000 (RD18), MT7981, IPQ40xx, OpenWrt ARM | `gcc-arm-linux-gnueabi` |
| `mipsel-unknown-linux-musl` | MIPS32r2 (Little-Endian, Soft-Float) | Mi Router 3 / 3G / Mini, MT7620, MT7621, Padavan, Entware | `mipsel-linux-muslsf-cross` |
| `aarch64-unknown-linux-musl` | ARM64 / AArch64 | Raspberry Pi 4/5, NanoPi, RK3568, Filogic 830 (64-bit) | `gcc-aarch64-linux-gnu` |
| `x86_64-unknown-linux-musl` | x86_64 | x86 mini-PCs, Proxmox, pfSense/OPNsense x86 VM | `musl-tools` (`musl-gcc`) |

---

#### 1. ARMv7 Musl Soft-Float (`armv7-unknown-linux-musleabi`)

Many modern budget routers (e.g. MediaTek Filogic MT7981 / Cortex-A53 running in 32-bit mode) use a soft-float musl userspace (`/lib/ld-musl-arm.so.1`).
Compiling with standard hard-float toolchains (`armhf`) causes `Illegal instruction` (SIGILL / exit 132).

```bash
# Install cross-compiler
apt install -y gcc-arm-linux-gnueabi

# Add Rust target
rustup target add armv7-unknown-linux-musleabi --toolchain nightly

# Build packed binary (~70 KB)
./build.sh armv7-unknown-linux-musleabi
# Output: target/armv7-unknown-linux-musleabi/release/nanoproxy
```

---

#### 2. MIPS Little-Endian Soft-Float (`mipsel-unknown-linux-musl`)

Routers based on MediaTek MT7620/MT7621 running Padavan, OpenWrt, or Entware require MIPS32r2 little-endian binaries. These chips lack hardware FPUs, so soft-float musl (`muslsf`) is strictly required.

Because upstream Rust's musl target links dynamic CRT stubs or expects hard-float by default, link statically with a muslsf cross-toolchain (e.g. built via `musl-cross-make`):

```bash
# Add Rust target
rustup target add mipsel-unknown-linux-musl --toolchain nightly

# Build packed binary (~190 KB)
./build.sh mipsel-unknown-linux-musl
# Output: target/mipsel-unknown-linux-musl/release/nanoproxy
```

The linker wrapper (`mipsel-gcc-wrapper`) in `.cargo/config.toml` passes `-static -no-pie` and explicitly pulls `libc.a` and `libgcc.a` to guarantee a 100% self-contained binary that runs even in read-only MTD partitions.

---

#### 3. ARM64 / AArch64 (`aarch64-unknown-linux-musl`)

For modern 64-bit ARM boards and routers:

```bash
# Install cross-compiler
apt install -y gcc-aarch64-linux-gnu

# Add Rust target
rustup target add aarch64-unknown-linux-musl --toolchain nightly

# Build
./build.sh aarch64-unknown-linux-musl
# Output: target/aarch64-unknown-linux-musl/release/nanoproxy
```

---

#### 4. x86_64 Musl (`x86_64-unknown-linux-musl`)

For x86 routers and Linux servers:

```bash
# Install musl tools
apt install -y musl-tools

# Add Rust target
rustup target add x86_64-unknown-linux-musl --toolchain nightly

# Build
./build.sh x86_64-unknown-linux-musl
# Output: target/x86_64-unknown-linux-musl/release/nanoproxy
```

### `.cargo/config.toml` Reference

Cross-linkers are configured in `.cargo/config.toml`:

```toml
[target.armv7-unknown-linux-musleabi]
linker = "arm-linux-gnueabi-gcc"

[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-gnu-gcc"

[target.mipsel-unknown-linux-musl]
linker = "/opt/mipsel-linux-muslsf-cross/bin/mipsel-gcc-wrapper"

[unstable]
build-std = ["std", "panic_abort"]
```
