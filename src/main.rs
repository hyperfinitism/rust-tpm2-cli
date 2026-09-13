// SPDX-License-Identifier: Apache-2.0

//! # rust-tpm2-cli
//!
//! ![SemVer: pre-release](https://img.shields.io/badge/tpm2--cli-pre--release-ffc0cb)
//! ![MSRV: 1.88.0](https://img.shields.io/badge/MSRV-1.88.0-39c5bb.svg)
//! [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-red.svg)](https://www.apache.org/licenses/LICENSE-2.0)
//!
//! <div align="center"><img src="https://raw.githubusercontent.com/hyperfinitism/rust-tpm2-cli/main/assets/logo-two-colour.png" alt="Logo of rust-tpm2-cli" width="25%" height="25%"></div>
//!
//! The `rust-tpm2-cli` crate provides a suite of Rust-based command-line tools for interacting with Trusted Platform Module 2.0 (TPM 2.0) devices.
//!
//! > [!NOTE]
//! > This project is heavily inspired by [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) and gratefully acknowledges the work of its contributors.
//! > Although the initial design attempted to preserve its subcommand and argument names, compatibility with the `tpm2-tools` command-line API is no longer a project goal.
//! > `rust-tpm2-cli` now defines an independent, intentionally different API.
//! > See the [Comparison with tpm2-tools](#comparison-with-tpm2-tools) section for details.
//!
//! ## Quick start
//!
//! ### Install dependencies
//!
//! - [Rust](https://rust-lang.org/): v1.88.0 or later
//! - [tpm2-tss](https://github.com/tpm2-software/tpm2-tss): v4.2.0 or later (C library)
//!
//! Install the latest Rust toolchain:
//!
//! ```bash
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//! source "$HOME/.cargo/env"
//! ```
//!
//! Install `tpm2-tss` from package manager (may be outdated):
//!
//! ```bash
//! sudo apt install -y libtss2-dev pkg-config
//! ```
//!
//! If the version of `tpm2-tss` available from the package manager is too old, build `tpm2-tss` from source:
//!
//! ```bash
//! # Install build dependencies
//! sudo apt update
//! sudo apt install -y \
//!     git autoconf autoconf-archive automake build-essential doxygen pkg-config \
//!     libtool libcmocka0 libcmocka-dev libcurl4-openssl-dev libftdi-dev libini-config-dev \
//!     libjson-c-dev libltdl-dev libssl-dev libusb-1.0-0-dev uthash-dev uuid-dev
//!
//! # Clone latest main and build
//! git clone --filter=blob:none https://github.com/tpm2-software/tpm2-tss
//! cd tpm2-tss
//! git checkout 506c5e6db0c8514f321dc16a0da2580483f3df04   # tag: 4.2.0
//! ./bootstrap
//! ./configure --prefix=/usr \
//!     --disable-fapi --disable-weakcrypto --disable-integration
//! make -j$(nproc)
//! sudo make install
//! sudo ldconfig
//! ```
//!
//! See also [Installation instructions for tpm2-tss](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).
//!
//! ### Build `rust-tpm2-cli`
//!
//! ```bash
//! git clone https://github.com/hyperfinitism/rust-tpm2-cli
//! cd rust-tpm2-cli
//! cargo build --release
//! # => ./target/release/tpm2
//! ```
//!
//! ### Generate man pages
//!
//! You can generate the `tpm2(1)` page and one page for each subcommand directly from the `clap` command definitions:
//!
//! ```bash
//! cargo xtask manpages
//! # => ./target/man/tpm2.1
//! # => ./target/man/tpm2-<subcommand>.1
//! ```
//!
//! Use `--out-dir` to select another output directory:
//!
//! ```bash
//! cargo xtask manpages --out-dir ./man
//! ```
//!
//! ### Configure TCTI
//!
//! The [TPM Command Transmission Interface (TCTI)](https://trustedcomputinggroup.org/resource/tss-tcti-specification/) is the abstraction layer within the TPM Software Stack (TSS) that defines how commands are transmitted to a TPM device.
//! `rust-tpm2-cli` reads the default TCTI from the `RUST_TPM2_CLI_TCTI` environment variable.
//! This can be overridden per invocation with the `--tcti, -T` global option.
//!
//! #### Using a platform TPM
//!
//! > [!CAUTION]
//! > The platform TPM may already be in use by the system for purposes such as measured boot, full-disk encryption, remote attestation and sealing/unsealing of credentials.
//! > Careless operations (such as clearing hierarchies or changing auth values) can irreversibly break these functions.
//! > Use a software TPM emulator such as `swtpm` or `mssim` for development and testing.
//! > See also [Using `swtpm`](#using-swtpm).
//!
//! ```bash
//! # Find TPM device paths, e.g., /dev/tpm0, /dev/tpmrm0
//! ls -l /dev/tpm*
//!
//! # Add current user to tss usergroup to grant access permissions to TPMRM
//! sudo usermod "$USER" -aG tss
//! newgrp tss
//!
//! # Set default TCTI to device:/dev/tpmrm0
//! export RUST_TPM2_CLI_TCTI="device:/dev/tpmrm0"
//! ```
//!
//! `/dev/tpm*` exposes the TPM character device provided by the kernel TPM driver.
//! Only one process can safely use this path at a time.
//! If you encounter a "device busy" error when using `/dev/tpm*`, it is likely because another process (such as `tpm2-abrmd`) already holds an exclusive session.
//!
//! In contrast, `/dev/tpmrm*` provides the in-kernel TPM 2.0 resource manager (TPMRM).
//! It virtualises handles and manages context swapping so that multiple processes can share the TPM safely.
//! For most applications, `/dev/tpmrm*` is the recommended device node.
//!
//! #### Using `tpm2-abrmd`
//!
//! [TPM2 Access Broker & Resource Manager (tpm2-abrmd)](https://github.com/tpm2-software/tpm2-abrmd) is a user space daemon that serves as an alternative to the in-kernel resource manager on older kernels (`< 4.12`) where `/dev/tpmrm*` is not available.
//!
//! ```bash
//! # Install tpm2-abrmd
//! sudo apt install -y tpm2-abrmd
//!
//! # Start tpm2-abrmd service
//! sudo systemctl start tpm2-abrmd.service
//!
//! # Check status
//! systemctl status tpm2-abrmd.service
//!
//! # Set default TCTI to tabrmd
//! # Note: Argument "bus_type=system" may be omitted
//! export RUST_TPM2_CLI_TCTI="tabrmd:bus_type=system"
//! ```
//!
//! #### Using `swtpm`
//!
//! [swtpm](https://github.com/stefanberger/swtpm) is a software TPM 2.0 emulator that runs entirely in user space.
//! It is safe for development and testing — its state is ephemeral and isolated from the platform TPM.
//! It is also useful for trying out `rust-tpm2-cli` on environments without a platform TPM.
//!
//! ```bash
//! # Install swtpm
//! sudo apt install -y swtpm
//!
//! mkdir -p /tmp/swtpm
//!
//! # Start swtpm
//! swtpm socket \
//!     --tpm2 \
//!     --tpmstate dir=/tmp/swtpm \
//!     --server type=tcp,port=2321 \
//!     --ctrl type=tcp,port=2322 \
//!     --flags startup-clear
//!
//! # In another terminal, set default TCTI to swtpm
//! export RUST_TPM2_CLI_TCTI="swtpm:host=localhost,port=2321"
//! ```
//!
//! ```bash
//! swtpm socket \
//!     --tpm2 \
//!     --tpmstate dir=/tmp/swtpm \
//!     --server type=unixio,path=/tmp/swtpm/swtpm.sock \
//!     --ctrl type=unixio,path=/tmp/swtpm/swtpm.sock.ctrl \
//!     --flags startup-clear
//!
//! export RUST_TPM2_CLI_TCTI="swtpm:path=/tmp/swtpm/swtpm.sock"
//! ```
//!
//! ## Usage
//!
//! ```bash
//! tpm2 [GLOBAL_OPTIONS...] <subcommand> [SUBCOMMAND_OPTIONS...]
//! ```
//!
//! For a full list of subcommands:
//!
//! ```bash
//! tpm2 -h
//! ```
//!
//! For details on a specific subcommand:
//!
//! ```bash
//! tpm2 <subcommand> -h
//! ```
//!
//! ### TPM Capabilities
//!
//! ```bash
//! # Print all supported queries
//! tpm2 getcap --list
//!
//! # Supported TPM 2.0 commands
//! tpm2 getcap commands
//!
//! # Available PCR bank
//! tpm2 getcap pcrs
//!
//! # Fixed and variable properties
//! tpm2 getcap properties-fixed
//! tpm2 getcap properties-variable
//!
//! # Supported elliptic curves for cryptography
//! tpm2 getcap ecc-curves
//!
//! # Persistent object handles
//! tpm2 getcap handles-persistent
//!
//! # NV index handles
//! tpm2 getcap handles-nv-index
//! ```
//!
//! ### Random
//!
//! ```bash
//! tpm2 getrandom 32 --hex
//! tpm2 getrandom 32 -o random.bin
//! ```
//!
//! ### Hash
//!
//! ```bash
//! echo "hello world" > message.dat
//! tpm2 hash message.dat -g sha384 --hex
//! tpm2 hash message.dat -g sha384 -o digest.bin -t ticket.bin
//! ```
//!
//! ### Sign
//!
//! ```bash
//! # Create a primary key under the owner hierarchy
//! tpm2 createprimary -C o -G ecc -c primary.ctx
//!
//! # Create an unrestricted signing key
//! tpm2 create -C file:primary.ctx -G ecc -r key.priv -u key.pub
//!
//! # Load the signing key
//! tpm2 load -C file:primary.ctx -r key.priv -u key.pub -c key.ctx
//!
//! # Hash a message
//! echo -n "message" > message.dat
//! tpm2 hash message.dat -g sha256 -o digest.bin
//!
//! # Sign the digest
//! tpm2 sign -c file:key.ctx -g sha256 -s ecdsa -d digest.bin -o sig.bin
//!
//! # Verify
//! tpm2 verifysignature -k key.pub -g sha256 -m message.dat -s sig.bin
//! tpm2 verifysignature -c file:key.ctx -d digest.bin -s sig.bin
//! ```
//!
//! ### Attestation
//!
//! ```bash
//! # Create EK
//! tpm2 createek -G ecc -c ek.ctx -u ek.pub
//! tpm2 evictcontrol 0x81010002 -c file:ek.ctx -C o
//!
//! # Create AK
//! tpm2 createak -C hex:0x81010002 -c ak.ctx -G ecc -g sha256 -u ak.pub -n ak.name
//! tpm2 evictcontrol 0x81000002 -c file:ak.ctx -C o
//!
//! # Generate a nonce for freshness
//! tpm2 getrandom 32 -o nonce.bin
//!
//! # Quote PCRs 0–7 signed by the AK
//! tpm2 quote -c hex:0x81000002 -l sha256:0,1,2,3,4,5,6,7 -q file:nonce.bin -m quote.bin -s sig.bin -o pcrs.bin
//!
//! # Verify the quote
//! tpm2 checkquote -u hex:0x81000002 -m quote.bin -s sig.bin -f pcrs.bin -l sha256:0,1,2,3,4,5,6,7 -q file:nonce.bin
//!     
//! # Verify quote signature only
//! tpm2 verifysignature -k ak.pub -g sha256 -m quote.bin -s sig.bin
//! ```
//!
//! ### Credential activation
//!
//! ```bash
//! # Create EK
//! tpm2 createek -G ecc -c ek.ctx -u ek.pub
//! tpm2 evictcontrol 0x81010002 -c file:ek.ctx -C o
//!
//! # Create AK
//! tpm2 createak -C hex:0x81010002 -c ak.ctx -G ecc -g sha256 -u ak.pub -n ak.name
//! tpm2 evictcontrol 0x81000002 -c file:ak.ctx -C o
//!
//! # Make credential
//! tpm2 getrandom 32 -o secret.bin
//! tpm2 makecredential -u ek.pub -s secret.bin -n ak.name -o cred_blob.bin
//!
//! # Activate credential
//! tpm2 activatecredential -c hex:0x81000002 -C hex:0x81010002 -i cred_blob.bin -o cert_info.bin
//!
//! # Verify
//! diff cert_info.bin secret.bin -s
//! ```
//!
//! ### Signed timestamp
//!
//! ```bash
//! # Create a primary key under the owner hierarchy
//! tpm2 createprimary -C o -G ecc -c primary.ctx
//!
//! # Create an unrestricted signing key
//! tpm2 create -C file:primary.ctx -G ecc -r key.priv -u key.pub
//!
//! # Load the signing key
//! tpm2 load -C file:primary.ctx -r key.priv -u key.pub -c key.ctx
//!
//! # Generate a nonce for freshness
//! tpm2 getrandom 32 -o nonce.bin
//!
//! # Get signed timestamp
//! tpm2 gettime -c file:key.ctx -g sha256 -q file:nonce.bin -o time.bin -s sig.bin
//!
//! # Verify signature
//! tpm2 verifysignature -k key.pub -g sha256 -m time.bin -s sig.bin
//! ```
//!
//! ### NV indexes
//!
//! #### Ordinary NV index
//!
//! ```bash
//! # Define (ordinary) NV index
//! tpm2 nvdefine 0x01000001 -C o -s 64
//!
//! # Write data to NV index
//! echo "hello world" > data.bin
//! tpm2 nvwrite 0x01000001 -C o -i data.bin
//!
//! # Read data from NV index
//! tpm2 nvread 0x01000001 -C o
//! tpm2 nvread 0x01000001 -C o -s $(stat -c %s data.bin) -o nv.bin
//! diff nv.bin data.bin -s
//!
//! # Undefine NV index
//! tpm2 nvundefine 0x01000001 -C o
//! ```
//!
//! #### NV extend index
//!
//! Like PCRs, NV extend indices can store hash chains.
//! The only permitted write operation is the extension of the hash chain.
//! The size parameter `-s` must be consistent with the hash algorithm parameter `-g`.
//!
//! ```bash
//! # Define NV extend index
//! tpm2 nvdefine 0x01000001 -C o -s 48 -g sha384 -a "nt=extend|ownerwrite|ownerread"
//!
//! # Extend PCR-like NV index
//! for i in {0..4}
//! do
//!   openssl rand 48 > random.bin
//!   tpm2 nvextend 0x01000001 -C o -i random.bin
//!   tpm2 nvread 0x01000001 -C o
//! done
//!
//! tpm2 nvundefine 0x01000001 -C o
//! ```
//!
//! #### NV Counter Index
//!
//! ```bash
//! # Define counter NV index
//! tpm2 nvdefine 0x01000001 -C o -s 8 -a "nt=counter|ownerwrite|ownerread"
//!
//! # Increment counter NV index
//! for i in {0..4}
//! do
//!   tpm2 nvincrement 0x01000001 -C o
//!   tpm2 nvread 0x01000001 -C o
//! done
//!
//! tpm2 nvundefine 0x01000001 -C o
//! ```
//!
//! ### PCRs
//!
//! ```bash
//! # Read PCR bank
//! tpm2 pcrread sha1:0,1,2+sha256:all
//! tpm2 pcrread sha256:16 -o pcr16.bin
//!
//! # Extend PCR 16
//! echo "hello world" > message.dat
//! tpm2 hash message.dat -g sha256 -o digest.bin
//! DIGEST_HEX=$(xxd -p digest.bin | tr -d '\n')
//!
//! tpm2 pcrextend 16:sha256=${DIGEST_HEX}
//! tpm2 pcrread sha256:16
//! # == cat pcr16.bin digest.bin | sha256sum
//!
//! # Reset PCR 16
//! tpm2 pcrreset 16
//! ```
//!
//! ## Comparison with tpm2-tools
//!
//! `rust-tpm2-cli` is inspired by `tpm2-tools`, but it is not a drop-in replacement and does not aim to preserve command-line compatibility.
//! Scripts written for one project generally need to be adapted before they can be used with the other.
//!
//! ### Implementation and TSS architecture
//!
//! | | `rust-tpm2-cli` | `tpm2-tools` |
//! | - | --------------- | ------------ |
//! | **Implementation language** | Rust | C |
//! | **Application-facing ESAPI** | [rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi) | [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) ESAPI |
//! | **Underlying TSS implementation** | Delegates TPM communication to the C-based `tpm2-tss` stack | All TSS layers are provided directly by the C-based `tpm2-tss` stack |
//!
//! The upstream `rust-tss-esapi` wraps the `tpm2-tss` ESAPI, which in turn uses the lower layers of the C-based `tpm2-tss` stack, so it is not a pure-Rust TSS implementation.
//! `rust-tpm2-cli` nevertheless benefits from Rust's memory-safety guarantees and type system throughout its own implementation and at the application-facing ESAPI boundary.
//! Commands use `rust-tss-esapi` directly wherever it provides a wrapper; commands not yet exposed by that library use raw ESYS only as a narrowly scoped fallback.
//!
//! ### Type-driven argument parsing
//!
//! `rust-tpm2-cli` follows the [“Parse, don't validate”](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) idiom as far as practical.
//! CLI strings are converted at the command-line boundary into domain types such as TPM handles, algorithms, authorization values, PCR selections, and command-specific enums.
//! Invalid combinations and values are therefore rejected by the argument parser ([`clap`](https://github.com/clap-rs/clap)) before TPM command execution whenever they can be determined without accessing external files or the TPM itself.
//!
//! ### CLI API and command coverage
//!
//! - **TPM command names are authoritative**:
//!   The TPM 2.0 Library Specification is the source of truth for TPM-facing subcommand names.
//!   For example, the TPM command `TPM2_EncryptDecrypt2` corresponds to the  `encryptdecrypt2` subcommand, not `encryptdecrypt`.
//!   (The latter should correspond to the deprecated `TPM2_EncryptDecrpt`.)
//!
//! - **Command coverage is independent of `tpm2-tools`**:
//!   The supported command sets are not identical, and `rust-tpm2-cli` exposes several TPM commands that are not implemented as `tpm2-tools` subcommands.
//!   Non-TPM utility commands are retained where useful, but their help text identifies them as utilities and names the TPM commands used to implement them.
//!
//! - **Handle and context sources are explicit**:
//!   Arguments that can refer to either a loaded TPM handle or a saved context require a `hex:` or `file:` prefix.
//!   For example, `hex:0x81010001` selects a handle while `file:key.ctx` selects a context file.
//!
//! - **Semantically valid input forms are accepted**:
//!   Some commands in `tpm2-tools` restrict arguments to hexadecimal handles for no particular TPM-level reason.
//!   `rust-tpm2-cli` also accepts a context file when the operation can resolve one safely.
//!
//! ### Logging
//!
//! `rust-tpm2-cli` uses [`flexi_logger`](https://github.com/emabee/flexi_logger) and provides global options for selecting the log level and writing logs to a file.
//! Detailed `Debug` and `Trace` instrumentation is not yet comprehensive and remains to be implemented.
//!
//! ## Licenses
//!
//! - The source code is licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
//! - The project logo assets are licensed under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

fn main() -> std::process::ExitCode {
    tpm2_cli::run()
}
