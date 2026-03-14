// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use flexi_logger::LevelFilter;
use std::path::PathBuf;

use crate::cmd;

#[derive(Parser)]
#[command(name = "tpm2", version, about = "Rust-based CLI tools for TPM 2.0")]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Parser)]
pub struct GlobalOpts {
    /// TCTI configuration (e.g. device:/dev/tpm0, mssim:host=localhost,port=2321)
    #[arg(short = 'T', long = "tcti", env = "TPM2TOOLS_TCTI")]
    pub tcti: Option<String>,

    /// Enable errata fixups
    #[arg(short = 'Z', long = "enable-errata")]
    pub enable_errata: bool,

    /// Verbosity level (Trace, Debug, Info, Warn, Error, Off)
    #[arg(short = 'v', long, default_value = "Info")]
    pub verbosity: LevelFilter,

    /// Log file path (default: None)
    #[arg(short = 'l', long = "log-file")]
    pub log_file: Option<PathBuf>,
}

macro_rules! tpm2_commands {
    ( $( $(#[$meta:meta])* $variant:ident($path:path) ),* $(,)? ) => {
        #[derive(Subcommand)]
        pub enum Commands {
            $( $(#[$meta])* $variant($path), )*
        }

        impl Commands {
            pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
                match self {
                    $( Self::$variant(c) => c.execute(global), )*
                }
            }
        }
    };
}

tpm2_commands! {
    /// Activate a credential and recover the secret
    Activatecredential(cmd::activatecredential::ActivateCredentialCmd),
    /// Certify that an object is loaded in the TPM
    Certify(cmd::certify::CertifyCmd),
    /// Certify creation data for an object
    Certifycreation(cmd::certifycreation::CertifyCreationCmd),
    /// Change auth value for an object or hierarchy
    Changeauth(cmd::changeauth::ChangeAuthCmd),
    /// Change the endorsement primary seed
    Changeeps(cmd::changeeps::ChangeEpsCmd),
    /// Change the platform primary seed
    Changepps(cmd::changepps::ChangePpsCmd),
    /// Verify a TPM quote
    Checkquote(cmd::checkquote::CheckQuoteCmd),
    /// Clear the TPM
    Clear(cmd::clear::ClearCmd),
    /// Enable or disable TPM2_Clear
    Clearcontrol(cmd::clearcontrol::ClearControlCmd),
    /// Adjust the clock rate
    Clockrateadjust(cmd::clockrateadjust::ClockRateAdjustCmd),
    /// Perform the first part of an ECC anonymous signing operation
    Commit(cmd::commit::CommitCmd),
    /// Create a child key
    Create(cmd::create::CreateCmd),
    /// Create an attestation key (AK) under an EK
    Createak(cmd::createak::CreateAkCmd),
    /// Create a TCG-compliant endorsement key (EK)
    Createek(cmd::createek::CreateEkCmd),
    /// Create a policy from a trial session
    Createpolicy(cmd::createpolicy::CreatePolicyCmd),
    /// Create a primary key
    Createprimary(cmd::createprimary::CreatePrimaryCmd),
    /// Decrypt data with a symmetric TPM key
    Decrypt(cmd::decrypt::DecryptCmd),
    /// Reset or configure dictionary attack lockout
    Dictionarylockout(cmd::dictionarylockout::DictionaryLockoutCmd),
    /// Duplicate an object for use on another TPM
    Duplicate(cmd::duplicate::DuplicateCmd),
    /// Generate an ephemeral ECDH key pair and compute a shared secret
    Ecdhkeygen(cmd::ecdhkeygen::EcdhKeygenCmd),
    /// Perform ECDH key exchange Z-point generation
    Ecdhzgen(cmd::ecdhzgen::EcdhZgenCmd),
    /// Create an ephemeral key for two-phase key exchange
    Ecephemeral(cmd::ecephemeral::EcEphemeralCmd),
    /// Encrypt data with a symmetric TPM key
    Encrypt(cmd::encrypt::EncryptCmd),
    /// Encrypt or decrypt data with a symmetric key
    Encryptdecrypt(cmd::encryptdecrypt::EncryptDecryptCmd),
    /// Parse and display a binary TPM2 event log
    Eventlog(cmd::eventlog::EventLogCmd),
    /// Make a transient object persistent (or evict a persistent object)
    Evictcontrol(cmd::evictcontrol::EvictControlCmd),
    /// Flush a context (handle) from the TPM
    Flushcontext(cmd::flushcontext::FlushContextCmd),
    /// Query TPM capabilities and properties
    Getcap(cmd::getcap::GetCapCmd),
    /// Get the command audit digest
    Getcommandauditdigest(cmd::getcommandauditdigest::GetCommandAuditDigestCmd),
    /// Get ECC curve parameters
    Geteccparameters(cmd::geteccparameters::GetEccParametersCmd),
    /// Retrieve the EK certificate from TPM NV storage
    Getekcertificate(cmd::getekcertificate::GetEkCertificateCmd),
    /// Get random bytes from the TPM
    Getrandom(cmd::getrandom::GetRandomCmd),
    /// Get the session audit digest
    Getsessionauditdigest(cmd::getsessionauditdigest::GetSessionAuditDigestCmd),
    /// Get the TPM self-test result
    Gettestresult(cmd::gettestresult::GetTestResultCmd),
    /// Get a signed timestamp from the TPM
    Gettime(cmd::gettime::GetTimeCmd),
    /// Compute a hash using the TPM
    Hash(cmd::hash::HashCmd),
    /// Enable or disable TPM hierarchies
    Hierarchycontrol(cmd::hierarchycontrol::HierarchyControlCmd),
    /// Compute HMAC using a TPM key
    Hmac(cmd::tpmhmac::HmacCmd),
    /// Import a wrapped key into the TPM
    Import(cmd::import::ImportCmd),
    /// Run incremental self-test on specified algorithms
    Incrementalselftest(cmd::incrementalselftest::IncrementalSelfTestCmd),
    /// Load a key into the TPM
    Load(cmd::load::LoadCmd),
    /// Load an external key into the TPM
    Loadexternal(cmd::loadexternal::LoadExternalCmd),
    /// Create a credential blob for a TPM key
    Makecredential(cmd::makecredential::MakeCredentialCmd),
    /// Certify the contents of an NV index
    Nvcertify(cmd::nvcertify::NvCertifyCmd),
    /// Define an NV index
    Nvdefine(cmd::nvdefine::NvDefineCmd),
    /// Extend data into an NV index
    Nvextend(cmd::nvextend::NvExtendCmd),
    /// Increment an NV counter
    Nvincrement(cmd::nvincrement::NvIncrementCmd),
    /// Read data from an NV index
    Nvread(cmd::nvread::NvReadCmd),
    /// Lock an NV index for reading
    Nvreadlock(cmd::nvreadlock::NvReadLockCmd),
    /// Read the public area of an NV index
    Nvreadpublic(cmd::nvreadpublic::NvReadPublicCmd),
    /// Set bits in an NV bit field
    Nvsetbits(cmd::nvsetbits::NvSetBitsCmd),
    /// Remove an NV index
    Nvundefine(cmd::nvundefine::NvUndefineCmd),
    /// Write data to an NV index
    Nvwrite(cmd::nvwrite::NvWriteCmd),
    /// Lock an NV index for writing
    Nvwritelock(cmd::nvwritelock::NvWriteLockCmd),
    /// Allocate PCR banks
    Pcrallocate(cmd::pcrallocate::PcrAllocateCmd),
    /// Extend a PCR with event data
    Pcrevent(cmd::pcrevent::PcrEventCmd),
    /// Extend a PCR with a digest
    Pcrextend(cmd::pcrextend::PcrExtendCmd),
    /// Read PCR values
    Pcrread(cmd::pcrread::PcrReadCmd),
    /// Reset a PCR register
    Pcrreset(cmd::pcrreset::PcrResetCmd),
    /// Extend a policy with PolicyAuthorize
    Policyauthorize(cmd::policyauthorize::PolicyAuthorizeCmd),
    /// Extend a policy using NV-stored policy
    Policyauthorizenv(cmd::policyauthorizenv::PolicyAuthorizeNvCmd),
    /// Extend a policy with PolicyAuthValue
    Policyauthvalue(cmd::policyauthvalue::PolicyAuthValueCmd),
    /// Extend a policy with PolicyCommandCode
    Policycommandcode(cmd::policycommandcode::PolicyCommandCodeCmd),
    /// Extend a policy with PolicyCounterTimer
    Policycountertimer(cmd::policycountertimer::PolicyCounterTimerCmd),
    /// Extend a policy with PolicyCpHash
    Policycphash(cmd::policycphash::PolicyCpHashCmd),
    /// Extend a policy with PolicyDuplicationSelect
    Policyduplicationselect(cmd::policyduplicationselect::PolicyDuplicationSelectCmd),
    /// Extend a policy with PolicyLocality
    Policylocality(cmd::policylocality::PolicyLocalityCmd),
    /// Extend a policy with PolicyNameHash
    Policynamehash(cmd::policynamehash::PolicyNameHashCmd),
    /// Extend a policy bound to NV index contents
    Policynv(cmd::policynv::PolicyNvCmd),
    /// Extend a policy with PolicyNvWritten
    Policynvwritten(cmd::policynvwritten::PolicyNvWrittenCmd),
    /// Extend a policy with PolicyOR
    Policyor(cmd::policyor::PolicyOrCmd),
    /// Extend a policy with PolicyPassword
    Policypassword(cmd::policypassword::PolicyPasswordCmd),
    /// Extend a policy with PolicyPCR
    Policypcr(cmd::policypcr::PolicyPcrCmd),
    /// Reset a policy session
    Policyrestart(cmd::policyrestart::PolicyRestartCmd),
    /// Extend a policy session with PolicySecret
    Policysecret(cmd::policysecret::PolicySecretCmd),
    /// Extend a policy with PolicySigned
    Policysigned(cmd::policysigned::PolicySignedCmd),
    /// Extend a policy with PolicyTemplate
    Policytemplate(cmd::policytemplate::PolicyTemplateCmd),
    /// Extend a policy with a ticket
    Policyticket(cmd::policyticket::PolicyTicketCmd),
    /// Decode and display a TPM data structure
    Print(cmd::print::PrintCmd),
    /// Generate a TPM quote
    Quote(cmd::quote::QuoteCmd),
    /// Decode a TPM response code
    Rcdecode(cmd::rcdecode::RcDecodeCmd),
    /// Read the TPM clock
    Readclock(cmd::readclock::ReadClockCmd),
    /// Read the public area of a loaded object
    Readpublic(cmd::readpublic::ReadPublicCmd),
    /// RSA decrypt data
    Rsadecrypt(cmd::rsadecrypt::RsaDecryptCmd),
    /// RSA encrypt data
    Rsaencrypt(cmd::rsaencrypt::RsaEncryptCmd),
    /// Run the TPM self-test
    Selftest(cmd::selftest::SelfTestCmd),
    /// Send a raw TPM command
    Send(cmd::send::SendCmd),
    /// Configure session attributes
    Sessionconfig(cmd::sessionconfig::SessionConfigCmd),
    /// Set the TPM clock
    Setclock(cmd::setclock::SetClockCmd),
    /// Set or clear command audit status
    Setcommandauditstatus(cmd::setcommandauditstatus::SetCommandAuditStatusCmd),
    /// Set the primary policy for a hierarchy
    Setprimarypolicy(cmd::setprimarypolicy::SetPrimaryPolicyCmd),
    /// Send TPM2_Shutdown
    Shutdown(cmd::shutdown::ShutdownCmd),
    /// Sign data with a TPM key
    Sign(cmd::sign::SignCmd),
    /// Start a TPM authorization session
    Startauthsession(cmd::startauthsession::StartAuthSessionCmd),
    /// Send TPM2_Startup
    Startup(cmd::startup::StartupCmd),
    /// Stir random data into the TPM RNG
    Stirrandom(cmd::stirrandom::StirRandomCmd),
    /// Test if algorithm parameters are supported
    Testparms(cmd::testparms::TestParmsCmd),
    /// Unseal data from a sealed object
    Unseal(cmd::unseal::UnsealCmd),
    /// Verify a signature using a TPM key
    Verifysignature(cmd::verifysignature::VerifySignatureCmd),
    /// Perform two-phase ECDH key exchange
    Zgen2phase(cmd::zgen2phase::Zgen2PhaseCmd),
}
