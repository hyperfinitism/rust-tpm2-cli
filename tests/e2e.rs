// SPDX-License-Identifier: Apache-2.0

//! Cross-command end-to-end integration tests.

mod common;

#[path = "e2e/attestation.rs"]
mod attestation;
#[path = "e2e/context_management.rs"]
mod context_management;
#[path = "e2e/credentials.rs"]
mod credentials;
#[path = "e2e/enhanced_authorization.rs"]
mod enhanced_authorization;
#[path = "e2e/non_volatile_storage.rs"]
mod non_volatile_storage;
#[path = "e2e/parameter_encryption.rs"]
mod parameter_encryption;
#[path = "e2e/sealed_objects.rs"]
mod sealed_objects;
#[path = "e2e/sequences.rs"]
mod sequences;
#[path = "e2e/signing.rs"]
mod signing;
