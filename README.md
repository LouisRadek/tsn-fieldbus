# TSN Fieldbus

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Linux](https://img.shields.io/badge/Platform-Linux-informational?style=flat&logo=linux)](https://kernel.org/)

A research prototype of a TSN-based fieldbus implemented in Rust for a Bachelor's thesis.

The system focuses on pragmatic core capabilities required for a prototype implementation:
- Device discovery and bootstrap on Layer 2
- Device configuration and lifecycle handling
- Cyclic process-data transport through Ethernet
- gRPC-based management and control plane
- Basic message authentication with pre-shared secrets

## Features

- Workspace-based architecture with dedicated crates for `master`, `slave`, shared `common` types, `demo`, and `integration-tests`
- Device State Machine
- Discovery protocol implementation for master/slave onboarding
- Layer-2 cyclic data exchange handler with stream configuration support
- Slave API over gRPC for status, process image updates, and control interactions
- Security Mechanisms (shared secret loading, authentication footer handling, discovery authentication)
- Deterministic integration testing via a mock Ethernet network (no root required for integration tests)
- Linux demo runtime that creates a reproducible virtual network using `ip link`

## Architecture

| Crate | Purpose |
| --- | --- |
| `common` | Shared protocol/data types, state machine utilities, security modules, and demo runtime helpers |
| `master` | Controller implementation: Discovery orchestration, L2 handling, and Slave API client |
| `slave` | Slave (sensor and actuator) implementation: Discovery listener, L2 handling, gRPC server, token/device status management |
| `demo` | End-to-end runnable scenario with virtual interfaces, logging, and post-run analysis |
| `tests` | Cross-crate integration tests with mocked datalink transport |

## Requirements

- Linux (demo runtime relies on `ip` and raw datalink functionality)
- Rust toolchain (>= edition 2024 workspace)
- `iproute2` installed (`ip` command)
- For demo execution: elevated privileges (`sudo`) or capabilities for raw sockets and interface setup
- Setting of the evironment variable `SHARED_SLAVE_KEY` with e.g. the command:
```bash
openssl rand -hex 32"
```

## Quick Start

### Build all crates

```bash
cargo build --workspace --release
```

### Run the demo scenario

The demo creates virtual Ethernet pairs and bridge interfaces, therefore root privileges are typically required.

```bash
sudo ./target/release/demo
```

After execution, summarized results are written to `./logs`.

## Documentation

- The underlying concept of this prototype is described in the Bachelor's thesis paper.
- In-source module and API documentation is available across the workspace crates.

Generate local Rust API docs:

```bash
cargo doc --workspace --no-deps --open
```

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).

## Disclaimer

This software is a research prototype provided "as is", without warranty of any kind. It is not intended for production deployment in safety-critical or industrial certification contexts.
