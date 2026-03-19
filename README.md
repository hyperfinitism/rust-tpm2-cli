# rust-tpm2-cli

![SemVer: pre-release](https://img.shields.io/badge/tpm2--cli-pre--release-ffc0cb)
![MSRV: 1.90.0](https://img.shields.io/badge/MSRV-1.90.0-39c5bb.svg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-red.svg)](https://www.apache.org/licenses/LICENSE-2.0)

<div align="center"><img src="https://raw.githubusercontent.com/hyperfinitism/rust-tpm2-cli/main/assets/logo-two-colour.png" alt="Logo of rust-tpm2-cli" width="25%" height="25%"></div>

The `rust-tpm2-cli` crate provides a suite of Rust-based command-line tools for interacting with Trusted Platform Module 2.0 (TPM 2.0) devices.

> [!NOTE]
> This project is heavily inspired by [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) and gratefully acknowledges the work of its contributors.
> The (sub)command names and CLI argument names are designed to be largely compatible with those of `tpm2-tools`.
> See the [Comparison with tpm2-tools](#comparison-with-tpm2-tools) section for details.

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

### Configure TCTI

The [TPM Command Transmission Interface (TCTI)](https://trustedcomputinggroup.org/resource/tss-tcti-specification/) is the abstraction layer within the TPM Software Stack (TSS) that defines how commands are transmitted to a TPM device.
`rust-tpm2-cli` reads the default TCTI from the `RUST_TPM2_CLI_TCTI` environment variable.
This can be overridden per invocation with the `--tcti, -T` global option.

#### Using a platform TPM

> [!CAUTION]
> A platform TPM may already be in use by the system for measured boot, full disk encryption, or remote attestation. Careless operations — such as clearing hierarchies or changing auth values — can irreversibly break these functions.
> Use a software TPM emulator such as `swtpm` or `mssim` for development and testing.
> See also [Using `swtpm`](#using-swtpm).

```bash
# Find TPM device paths, e.g., /dev/tpm0, /dev/tpmrm0
ls -l /dev/tpm*

# Add current user to tss usergroup to grant access permissions to TPMRM
sudo usermod "$USER" -aG tss
newgrp tss

# Set default TCTI to device:/dev/tpmrm0
export RUST_TPM2_CLI_TCTI="device:/dev/tpmrm0"
```

`/dev/tpm*` exposes the TPM character device provided by the kernel TPM driver.
Only one process can safely use this path at a time.
If you encounter a "device busy" error when using `/dev/tpm*`, it is likely because another process (such as `tpm2-abrmd`) already holds an exclusive session.

In contrast, `/dev/tpmrm*` provides the in-kernel TPM 2.0 resource manager (TPMRM).
It virtualises handles and manages context swapping so that multiple processes can share the TPM safely.
For most applications, `/dev/tpmrm*` is the recommended device node.

#### Using `tpm2-abrmd`

[TPM2 Access Broker & Resource Manager (tpm2-abrmd)](https://github.com/tpm2-software/tpm2-abrmd) is a user space daemon that serves as an alternative to the in-kernel resource manager on older kernels (`< 4.12`) where `/dev/tpmrm*` is not available.

```bash
# Install tpm2-abrmd
sudo apt install -y tpm2-abrmd

# Start tpm2-abrmd service
sudo systemctl start tpm2-abrmd.service

# Check status
systemctl status tpm2-abrmd.service

# Set default TCTI to tabrmd
# Note: Argument "bus_type=system" may be omitted
export RUST_TPM2_CLI_TCTI="tabrmd:bus_type=system"
```

#### Using `swtpm`

[swtpm](https://github.com/stefanberger/swtpm) is a software TPM 2.0 emulator that runs entirely in user space.
It is safe for development and testing — its state is ephemeral and isolated from the platform TPM.
It is also useful for trying out `rust-tpm2-cli` on environments without a platform TPM.

```bash
# Install swtpm
sudo apt install -y swtpm

# Start swtpm
mkdir -p /tmp/swtpm
swtpm socket \
    --tpmstate dir=/tmp/swtpm \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags startup-clear

# In another terminal, set default TCTI to swtpm
export RUST_TPM2_CLI_TCTI="swtpm:host=localhost,port=2321"
```

## Usage

```bash
tpm2 [GLOBAL_OPTIONS...] <subcommand> [SUBCOMMAND_OPTIONS]
```

For a full list of subcommands:

```bash
tpm2 -h
```

For details on a specific subcommand:

```bash
tpm2 <subcommand> -h
```

### TPM Capabilities

```bash
# Print all supported capability names (ecc-curves, handles-persistent, ...)
tpm2 getcap --list

# Supported elliptic curves for cryptography
tpm2 getcap ecc-curves

# Persistent object handles
tpm2 getcap handles-persistent

# NV index handles
tpm2 getcap handles-nv-index

# PCR handles (typically 0x0..0x17, i.e., 0..23)
tpm2 getcap handles-pcr
```

### Random

```bash
tpm2 getrandom 32 --hex
tpm2 getrandom 32 -o random.bin
```

### Hash

```bash
echo "hello world" > message.dat
tpm2 hash message.dat -g sha384 --hex
tpm2 hash message.dat -g sha384 -o digest.bin -t ticket.bin
```

### Sign

```bash
# Create a primary key under the owner hierarchy
tpm2 createprimary -C o -G ecc -c primary.ctx

# Create an unrestricted signing key
tpm2 create -C primary.ctx -G ecc -u key.pub -r key.priv

# Load the signing key
tpm2 load -C primary.ctx -u key.pub -r key.priv -c key.ctx

# Hash a message
echo -n "message" > message.dat
tpm2 hash message.dat -g sha256 -o digest.bin

# Sign the digest
tpm2 sign -c key.ctx -g sha256 -s ecdsa -d digest.bin -o sig.bin

# Verify
tpm2 verifysignature -c key.ctx -g sha256 -m message.dat -s sig.bin
tpm2 verifysignature -c key.ctx -d digest.bin -s sig.bin
```

### Attestation

```bash
# Create and persist an Endorsement Key (EK)
tpm2 createek -c ek.ctx -G ecc -u ek.pub
tpm2 evictcontrol 0x81010001 -C o -c ek.ctx

# Create and persist an Attestation Key (AK) 
tpm2 createak -C ek.ctx -c ak.ctx -G ecc -u ak.pub
tpm2 evictcontrol 0x81000002 -C o -c ak.ctx

# Generate a nonce for freshness
tpm2 getrandom 32 -o nonce.bin

# Quote PCRs 0–7 signed by the AK
tpm2 quote -H 0x81000002 -l sha256:0,1,2,3,4,5,6,7 \
    --qualification-file nonce.bin \
    -m quote.bin -s sig.bin -o pcrs.bin

# Verify the quote
tpm2 checkquote -u ak.ctx -m quote.bin -s sig.bin \
    --qualification-file nonce.bin \
    -f pcrs.bin

# Verify quote signature only
tpm2 verifysignature -c ak.ctx -g sha256 -m quote.bin -s sig.bin
```

### NV indexes

```bash
# Define NV index
tpm2 nvdefine 0x01400002 -s 64 -C o

# Write binary file to NV index
openssl rand 64 > random.bin
tpm2 nvwrite 0x01400002 -i random.bin -C o

# Read data from NV index
tpm2 nvread 0x01400002 -C o

# Undefine NV index
tpm2 nvundefine 0x01400002 -C o
```

### PCRs

```bash
# Read PCR bank
tpm2 pcrread sha1:0,1,2+sha256:all
tpm2 pcrread sha256:23 -o pcr23.bin

# Extend PCR 23
echo "hello world" > message.dat
tpm2 hash message.dat -g sha256 -o digest.bin
DIGEST_HEX=$(xxd -p digest.bin | tr -d '\n')

tpm2 pcrextend 23:sha256=${DIGEST_HEX}
tpm2 pcrread sha256:23
# == cat pcr23.bin digest.bin | sha256sum

# Reset PCR 23
tpm2 pcrreset 23
```

## Comparison with tpm2-tools

While broadly following the `tpm2-tools` APIs, `rust-tpm2-cli` is a from-scratch implementation.
The key differences are:

| - | `rust-tpm2-cli` | `tpm2-tools` |
| - | --------------- | ------------ |
| **Language** | Rust | C |
| **TPM Software Stack (TSS)** | [rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi) | [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) |
| **Binary size order**\* | several MB | sub MB |

> \* The size of the binary depends on both the version and the build environment.
> This comparison uses `tpm2-tools` v5.7 and `rust-tpm2-cli` latest (at the time of writing this document).

`tpm2-tools` has a significantly smaller binary footprint, making it a better fit for resource-constrained environments such as IoT devices with limited storage or memory.
It also benefits from a long track record and broad backward compatibility.

`rust-tpm2-cli` trades binary size for Rust's memory safety guarantees, rich type system, and expressive language features, which reduce entire classes of bugs at compile time.

### API refinements

`rust-tpm2-cli` introduces a number of deliberate improvements (breaking changes) for clarity and consistency:

- **Explicit handle vs. context arguments**:
  Where `tpm2-tools` accepts either a TPM handle (hex string) or a context file path through a single argument, `rust-tpm2-cli` provides dedicated arguments for each, making the type of the input unambiguous.

- **Extended context file support**:
  Some arguments in `tpm2-tools` accept only a TPM handle in hex string form without an apparent reason.
  `rust-tpm2-cli` removes this restriction and allows a context file to be specified wherever it is semantically appropriate.

- **Subcommand splitting**:
  Subcommands that conflate distinct operations have been separated.
  For example, the `encryptdecrypt` subcommand of `tpm2-tools` is split into two dedicated subcommands `encrypt` and `decrypt`.
  (At the moment, `encryptdecrypt` is kept for compatibility.)

- **Flexible logging**:
  `rust-tpm2-cli` uses [flexi_logger](https://github.com/emabee/flexi_logger) for flexible logging control via CLI flags.
  Logs can also be written to a file.

## Licenses

- The source code is licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
- The project logo assets are licensed under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
