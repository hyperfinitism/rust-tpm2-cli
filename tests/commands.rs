// SPDX-License-Identifier: Apache-2.0

//! Command-scoped integration tests organised by the TPM 2.0 Library Specification,
//! Part 3: Commands.

mod common;

// Section 9
#[path = "commands/startup.rs"]
mod startup_commands;
// Section 10
#[path = "commands/testing.rs"]
mod testing;
// Section 11
#[path = "commands/session_commands.rs"]
mod session_commands;
// Section 12
#[path = "commands/object_commands.rs"]
mod object_commands;
// Section 13
#[path = "commands/duplication_commands.rs"]
mod duplication_commands;
// Section 14
#[path = "commands/asymmetric_primitives.rs"]
mod asymmetric_primitives;
// Section 15
#[path = "commands/symmetric_primitives.rs"]
mod symmetric_primitives;
// Section 16
#[path = "commands/random_number_generator.rs"]
mod random_number_generator;
// Section 17
#[path = "commands/hash_hmac_event_signature_sequences.rs"]
mod hash_hmac_event_signature_sequences;
// Section 18
#[path = "commands/attestation_commands.rs"]
mod attestation_commands;
// Section 19
#[path = "commands/ephemeral_ec_keys.rs"]
mod ephemeral_ec_keys;
// Section 20
#[path = "commands/signing_and_signature_verification.rs"]
mod signing_and_signature_verification;
// Section 21
#[path = "commands/command_audit.rs"]
mod command_audit;
// Section 22
#[path = "commands/integrity_collection.rs"]
mod integrity_collection;
// Section 23
#[path = "commands/enhanced_authorization.rs"]
mod enhanced_authorization;
// Section 24
#[path = "commands/hierarchy_commands.rs"]
mod hierarchy_commands;
// Section 25
#[path = "commands/dictionary_attack_functions.rs"]
mod dictionary_attack_functions;
// Section 26
#[path = "commands/miscellaneous_management_functions.rs"]
mod miscellaneous_management_functions;
// Section 27
#[path = "commands/field_upgrade.rs"]
mod field_upgrade;
// Section 28
#[path = "commands/context_management.rs"]
mod context_management;
// Section 29
#[path = "commands/clocks_and_timers.rs"]
mod clocks_and_timers;
// Section 30
#[path = "commands/capability_commands.rs"]
mod capability_commands;
// Section 31
#[path = "commands/non_volatile_storage.rs"]
mod non_volatile_storage;
// Section 32
#[path = "commands/attached_components.rs"]
mod attached_components;
// Section 33
#[path = "commands/authenticated_countdown_timer.rs"]
mod authenticated_countdown_timer;
// Section 34
#[path = "commands/vendor_specific.rs"]
mod vendor_specific;
