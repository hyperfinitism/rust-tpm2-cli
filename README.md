
<p align="center">
    <img src="assets/logo-two-colour.png" alt="Logo of rust-tpm2-cli" width="25%" height="25%">
</p>

# rust-tpm2-cli

![SemVer](https://img.shields.io/badge/tpm2--cli-pre--release-ffc0cb)
[![MSRV](https://img.shields.io/badge/MSRV-1.90.0-39c5bb.svg)](https://doc.rust-lang.org/stable/releases.html#version-1900-2025-09-18)
[![License](https://img.shields.io/badge/License-Apache--2.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

**rust-tpm2-cli** is a suite of Rust-based command-line tools for interacting
with Trusted Platform Module 2.0 (TPM 2.0) devices.

> [!NOTE]
> This project is heavily inspired by [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
> and gratefully acknowledges the work of its contributors.
> The (sub)command names and CLI argument names are designed to be largely
> compatible with those of `tpm2-tools`. See the [Comparison with tpm2-tools](#comparison-with-tpm2-tools)
> section for details.

## Quick start

### Install dependencies

```bash
sudo apt update
sudo apt install -y build-essential clang libtss2-dev pkg-config

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Build `rust-tpm2-cli`

```bash
git clone https://github.com/hyperfinitism/rust-tpm2-cli
cd rust-tpm2-cli
cargo build -r
# => ./target/release/tpm2
```

### Set up a native TPM (hardware or vTPM)

This applies to physical TPM chips and virtual TPMs (vTPMs) exposed by
hypervisors (e.g., QEMU, Hyper-V, Google Cloud vTPM).

> [!CAUTION]
> Operations on a native TPM can affect the entire system — clearing hierarchies,
> changing auth values, or modifying NV storage may break measured boot, disk
> encryption (e.g., BitLocker, LUKS), or remote attestation. Use `swtpm` for
> development and testing unless you specifically need a native TPM.

```bash
# Add current user to tss usergroup
sudo usermod "$USER" -aG tss
newgrp tss

# Check TPM device path(s), e.g., /dev/tpm0
ls -l /dev/tpm*

# Set TPM device path used by rust-tpm2-cli
export RUST_TPM2_CLI_TCTI="device:/dev/tpm0"
```

### Set up swtpm (software TPM simulator)

[swtpm](https://github.com/stefanberger/swtpm) provides a TPM 2.0 simulator
that runs entirely in user space. It is safe for development, testing, and CI —
its state is ephemeral and isolated from the host system.

```bash
sudo apt install -y swtpm
```

Start the simulator:

```bash
mkdir -p /tmp/swtpm
swtpm socket \
    --tpmstate dir=/tmp/swtpm \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags startup-clear

# In another terminal:
export RUST_TPM2_CLI_TCTI="swtpm:host=localhost,port=2321"
```

### Run integration tests

The test suite uses `swtpm`. Each test script starts its own simulator instance
automatically — no native TPM is needed.

```bash
sudo apt install -y swtpm   # if not already installed

# Build and run all tests
bash tests/run_all.sh
```

## Usage

Under construction.

## Comparison with tpm2-tools

While broadly following the `tpm2-tools` APIs, `rust-tpm2-cli` is a from-scratch implementation. The key differences are:

| | `tpm2-tools` | `rust-tpm2-cli` |
|---|---|---|
| **Language** | C | Rust |
| **TPM Software Stack (TSS)** | [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) | [rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi) |
| **Binary size order**\* | sub MB | several MB |

>  \* The size of the binary depends on both the version and the build environment. This comparison uses `tpm2-tools` v5.7 and `rust-tpm2-cli` latest (at the time of writing this document).

`tpm2-tools` has a significantly smaller binary footprint, making it a better fit for resource-constrained environments such as IoT devices with limited storage or memory. It also benefits from a long track record and broad backward compatibility.

`rust-tpm2-cli` trades binary size for Rust's memory safety guarantees, rich type system, and expressive language features, which reduce entire classes of bugs at compile time.

### API refinements

`rust-tpm2-cli` introduces a number of deliberate improvements (breaking changes) for clarity and consistency:

- **Explicit handle vs. context arguments**: Where `tpm2-tools` accepts either a TPM handle (hex string) or a context file path through a single argument, `rust-tpm2-cli` provides dedicated arguments for each, making the type of the input unambiguous.

- **Extended context file support**: Some arguments in `tpm2-tools` accept only a TPM handle in hex string form without an apparent reason. `rust-tpm2-cli` removes this restriction and allows a context file to be specified wherever it is semantically appropriate.

- **Subcommand splitting**: Subcommands that conflate distinct operations have been separated. For example, the `encryptdecrypt` subcommand of `tpm2-tools` is split into two dedicated subcommands `encrypt` and `decrypt`. (At the moment, `encryptdecrypt` is kept for compatibility.)

- **Flexible logging**: rust-tpm2-cli uses [flexi_logger](https://github.com/emabee/flexi_logger) for flexible logging control via CLI flags. Logs can also be written to a file.

## Licenses

- The source code is licensed under [Apache-2.0](LICENSE).
- The project logo assets (`assets/`) are licensed under [CC0-1.0](assets/LICENSE-LOGO).
