// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use flexi_logger::LevelFilter;
use std::path::PathBuf;

use crate::cmd;
use crate::parse;
use crate::tcti::TctiConfig;

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
    /// TCTI configuration (e.g. device:/dev/tpm0, swtpm:host=localhost,port=2321)
    #[arg(short = 'T', long = "tcti", env = "RUST_TPM2_CLI_TCTI", value_parser = parse::parse_tcti_config)]
    pub tcti: Option<TctiConfig>,

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
    /// Recover a credential protected for a TPM object.
    ///
    /// Wraps TPM2_ActivateCredential.
    Activatecredential(cmd::activatecredential::ActivateCredentialCmd),
    /// Produce signed evidence that an object is loaded and self-consistent.
    ///
    /// Wraps TPM2_Certify.
    Certify(cmd::certify::CertifyCmd),
    /// Attest to the association between an object and its creation data.
    ///
    /// Wraps TPM2_CertifyCreation.
    Certifycreation(cmd::certifycreation::CertifyCreationCmd),
    /// Generate X.509 certificate components for a loaded object.
    ///
    /// Wraps TPM2_CertifyX509, deprecated since TPM 2.0 Library version 184.
    Certifyx509(cmd::certifyx509::CertifyX509Cmd),
    /// Change the authorization value of an object or hierarchy.
    ///
    /// Utility that invokes TPM2_ObjectChangeAuth or TPM2_HierarchyChangeAuth for the selected target.
    Changeauth(cmd::changeauth::ChangeAuthCmd),
    /// Replace the endorsement primary seed and flush affected objects.
    ///
    /// Wraps TPM2_ChangeEPS.
    Changeeps(cmd::changeeps::ChangeEpsCmd),
    /// Replace the platform primary seed and flush affected objects.
    ///
    /// Wraps TPM2_ChangePPS.
    Changepps(cmd::changepps::ChangePpsCmd),
    /// Validate a quote, its signature, and optional PCR expectations.
    ///
    /// Utility that verifies TPM2_Quote output using TPM2_Hash and TPM2_VerifySignature.
    Checkquote(cmd::checkquote::CheckQuoteCmd),
    /// Remove objects and authorization values associated with TPM ownership.
    ///
    /// Wraps TPM2_Clear.
    Clear(cmd::clear::ClearCmd),
    /// Enable or disable execution of TPM2_Clear.
    ///
    /// Wraps TPM2_ClearControl.
    Clearcontrol(cmd::clearcontrol::ClearControlCmd),
    /// Adjust the rate at which the TPM clock advances.
    ///
    /// Wraps TPM2_ClockRateAdjust.
    Clockrateadjust(cmd::clockrateadjust::ClockRateAdjustCmd),
    /// Advance the TPM clock to a caller-selected value.
    ///
    /// Wraps TPM2_ClockSet.
    Clockset(cmd::clockset::ClockSetCmd),
    /// Perform the first phase of an anonymous ECC signing operation.
    ///
    /// Wraps TPM2_Commit.
    Commit(cmd::commit::CommitCmd),
    /// Restore a previously saved object or session context.
    ///
    /// Wraps TPM2_ContextLoad.
    Contextload(cmd::contextload::ContextLoadCmd),
    /// Save a loaded object or session context outside the TPM.
    ///
    /// Wraps TPM2_ContextSave.
    Contextsave(cmd::contextsave::ContextSaveCmd),
    /// Create an object protected by a parent object.
    ///
    /// Wraps TPM2_Create.
    Create(cmd::create::CreateCmd),
    /// Create and load a profile-oriented attestation key beneath an endorsement key.
    ///
    /// Utility implemented with TPM2_Create, TPM2_Load, and TPM2_ReadPublic.
    Createak(cmd::createak::CreateAkCmd),
    /// Create a TCG profile-oriented endorsement key and optionally persist it.
    ///
    /// Utility implemented with TPM2_CreatePrimary and TPM2_EvictControl.
    Createek(cmd::createek::CreateEkCmd),
    /// Calculate a simple policy digest in a trial session.
    ///
    /// Utility implemented with TPM2_StartAuthSession, policy commands, and TPM2_PolicyGetDigest.
    Createpolicy(cmd::createpolicy::CreatePolicyCmd),
    /// Create and load a primary object under a hierarchy.
    ///
    /// Wraps TPM2_CreatePrimary.
    Createprimary(cmd::createprimary::CreatePrimaryCmd),
    /// Reset dictionary-attack lockout or configure its thresholds and recovery timers.
    ///
    /// Utility that invokes TPM2_DictionaryAttackLockReset or TPM2_DictionaryAttackParameters.
    Dictionarylockout(cmd::dictionarylockout::DictionaryLockoutCmd),
    /// Duplicate an object for use under another parent.
    ///
    /// Wraps TPM2_Duplicate.
    Duplicate(cmd::duplicate::DuplicateCmd),
    /// Generate an ephemeral ECDH key pair and its shared secret.
    ///
    /// Wraps TPM2_ECDH_KeyGen.
    Ecdhkeygen(cmd::ecdhkeygen::EcdhKeygenCmd),
    /// Compute an ECDH shared secret with a loaded private key.
    ///
    /// Wraps TPM2_ECDH_ZGen.
    Ecdhzgen(cmd::ecdhzgen::EcdhZgenCmd),
    /// Generate an ephemeral key for a two-phase key exchange.
    ///
    /// Wraps TPM2_EC_Ephemeral.
    Ecephemeral(cmd::ecephemeral::EcEphemeralCmd),
    /// Encrypt or decrypt data with a symmetric TPM key.
    ///
    /// Wraps TPM2_EncryptDecrypt2.
    Encryptdecrypt2(cmd::encryptdecrypt2::EncryptDecrypt2Cmd),
    /// Parse and display a binary TCG event log.
    ///
    /// Client-side utility; it does not invoke a TPM command.
    Eventlog(cmd::eventlog::EventLogCmd),
    /// Persist a transient object or evict a persistent object.
    ///
    /// Wraps TPM2_EvictControl.
    Evictcontrol(cmd::evictcontrol::EvictControlCmd),
    /// Remove one or more loaded contexts from TPM memory.
    ///
    /// Wraps TPM2_FlushContext; bulk modes use TPM2_GetCapability and repeat the command.
    Flushcontext(cmd::flushcontext::FlushContextCmd),
    /// Query algorithms, handles, properties, and other TPM capabilities.
    ///
    /// Wraps TPM2_GetCapability.
    Getcap(cmd::getcap::GetCapCmd),
    /// Return the current command audit digest in a signed attestation.
    ///
    /// Wraps TPM2_GetCommandAuditDigest.
    Getcommandauditdigest(cmd::getcommandauditdigest::GetCommandAuditDigestCmd),
    /// Return the parameters of an ECC curve supported by the TPM.
    ///
    /// Wraps TPM2_ECC_Parameters.
    Geteccparameters(cmd::geteccparameters::GetEccParametersCmd),
    /// Retrieve an endorsement-key certificate from a profile-defined NV index.
    ///
    /// Utility implemented with TPM2_NV_ReadPublic and TPM2_NV_Read.
    Getekcertificate(cmd::getekcertificate::GetEkCertificateCmd),
    /// Return random bytes generated by the TPM.
    ///
    /// Wraps TPM2_GetRandom.
    Getrandom(cmd::getrandom::GetRandomCmd),
    /// Return the current audit digest of a session in a signed attestation.
    ///
    /// Wraps TPM2_GetSessionAuditDigest.
    Getsessionauditdigest(cmd::getsessionauditdigest::GetSessionAuditDigestCmd),
    /// Return data and status from the most recent TPM self-test.
    ///
    /// Wraps TPM2_GetTestResult.
    Gettestresult(cmd::gettestresult::GetTestResultCmd),
    /// Return TPM time and clock data in a signed attestation.
    ///
    /// Wraps TPM2_GetTime.
    Gettime(cmd::gettime::GetTimeCmd),
    /// Compute a digest and validation ticket for a message.
    ///
    /// Wraps TPM2_Hash.
    Hash(cmd::hash::HashCmd),
    /// Start an incremental hash sequence.
    ///
    /// Wraps TPM2_HashSequenceStart.
    Hashsequencestart(cmd::hashsequencestart::HashSequenceStartCmd),
    /// Enable or disable a hierarchy and its associated NV storage.
    ///
    /// Wraps TPM2_HierarchyControl.
    Hierarchycontrol(cmd::hierarchycontrol::HierarchyControlCmd),
    /// Compute an HMAC over a message with a loaded key.
    ///
    /// Wraps TPM2_HMAC.
    Hmac(cmd::tpmhmac::HmacCmd),
    /// Start an incremental HMAC sequence with a loaded key.
    ///
    /// Wraps TPM2_HMAC_Start.
    Hmacsequencestart(cmd::hmacsequencestart::HmacSequenceStartCmd),
    /// Import a duplicated object beneath a new parent.
    ///
    /// Wraps TPM2_Import.
    Import(cmd::import::ImportCmd),
    /// Test selected algorithms and return those still requiring testing.
    ///
    /// Wraps TPM2_IncrementalSelfTest through raw ESYS because rust-tss-esapi has no wrapper.
    Incrementalselftest(cmd::incrementalselftest::IncrementalSelfTestCmd),
    /// Load an object created beneath a parent into TPM memory.
    ///
    /// Wraps TPM2_Load.
    Load(cmd::load::LoadCmd),
    /// Load an externally generated public or sensitive object.
    ///
    /// Wraps TPM2_LoadExternal.
    Loadexternal(cmd::loadexternal::LoadExternalCmd),
    /// Protect a credential so it can be activated by a particular TPM object.
    ///
    /// Wraps TPM2_MakeCredential.
    Makecredential(cmd::makecredential::MakeCredentialCmd),
    /// Attest to the contents of an NV index or a portion of it.
    ///
    /// Wraps TPM2_NV_Certify.
    Nvcertify(cmd::nvcertify::NvCertifyCmd),
    /// Change the authorization value for an NV index.
    ///
    /// Wraps TPM2_NV_ChangeAuth.
    Nvchangeauth(cmd::nvchangeauth::NvChangeAuthCmd),
    /// Define and initialize the metadata for an NV index.
    ///
    /// Wraps TPM2_NV_DefineSpace.
    Nvdefine(cmd::nvdefine::NvDefineCmd),
    /// Hash new data into an extend-type NV index.
    ///
    /// Wraps TPM2_NV_Extend.
    Nvextend(cmd::nvextend::NvExtendCmd),
    /// Write-lock every NV index with the global-lock attribute set.
    ///
    /// Wraps TPM2_NV_GlobalWriteLock.
    Nvglobalwritelock(cmd::nvglobalwritelock::NvGlobalWriteLockCmd),
    /// Increment a counter-type NV index.
    ///
    /// Wraps TPM2_NV_Increment.
    Nvincrement(cmd::nvincrement::NvIncrementCmd),
    /// Read bytes from an NV index.
    ///
    /// Wraps TPM2_NV_Read.
    Nvread(cmd::nvread::NvReadCmd),
    /// Prevent further reads from a read-stclear NV index until restart.
    ///
    /// Wraps TPM2_NV_ReadLock.
    Nvreadlock(cmd::nvreadlock::NvReadLockCmd),
    /// Return the public metadata and name of an NV index.
    ///
    /// Wraps TPM2_NV_ReadPublic.
    Nvreadpublic(cmd::nvreadpublic::NvReadPublicCmd),
    /// Set selected bits in a bit-field NV index.
    ///
    /// Wraps TPM2_NV_SetBits.
    Nvsetbits(cmd::nvsetbits::NvSetBitsCmd),
    /// Remove an ordinary NV index.
    ///
    /// Wraps TPM2_NV_UndefineSpace.
    Nvundefine(cmd::nvundefine::NvUndefineCmd),
    /// Remove an NV index with the policy-delete attribute set.
    ///
    /// Wraps TPM2_NV_UndefineSpaceSpecial.
    Nvundefinespacespecial(cmd::nvundefinespacespecial::NvUndefineSpaceSpecialCmd),
    /// Write bytes to an NV index.
    ///
    /// Wraps TPM2_NV_Write.
    Nvwrite(cmd::nvwrite::NvWriteCmd),
    /// Prevent further writes to an NV index according to its attributes.
    ///
    /// Wraps TPM2_NV_WriteLock.
    Nvwritelock(cmd::nvwritelock::NvWriteLockCmd),
    /// Configure the PCR banks available after the next TPM reset.
    ///
    /// Wraps TPM2_PCR_Allocate.
    Pcrallocate(cmd::pcrallocate::PcrAllocateCmd),
    /// Hash event data in the TPM and extend the resulting digests into a PCR.
    ///
    /// Wraps TPM2_PCR_Event.
    Pcrevent(cmd::pcrevent::PcrEventCmd),
    /// Extend one or more caller-provided digests into a PCR.
    ///
    /// Wraps TPM2_PCR_Extend.
    Pcrextend(cmd::pcrextend::PcrExtendCmd),
    /// Read selected PCR values and their update counter.
    ///
    /// Wraps TPM2_PCR_Read.
    Pcrread(cmd::pcrread::PcrReadCmd),
    /// Reset a resettable PCR in every allocated bank.
    ///
    /// Wraps TPM2_PCR_Reset.
    Pcrreset(cmd::pcrreset::PcrResetCmd),
    /// Set the authorization policy for a PCR or PCR group.
    ///
    /// Wraps TPM2_PCR_SetAuthPolicy.
    Pcrsetauthpolicy(cmd::pcrsetauthpolicy::PcrSetAuthPolicyCmd),
    /// Change the authorization value for a PCR or PCR group.
    ///
    /// Wraps TPM2_PCR_SetAuthValue.
    Pcrsetauthvalue(cmd::pcrsetauthvalue::PcrSetAuthValueCmd),
    /// Replace a policy digest with one approved by an authorized key.
    ///
    /// Wraps TPM2_PolicyAuthorize.
    Policyauthorize(cmd::policyauthorize::PolicyAuthorizeCmd),
    /// Replace a policy digest with an approved policy stored in NV.
    ///
    /// Wraps TPM2_PolicyAuthorizeNV.
    Policyauthorizenv(cmd::policyauthorizenv::PolicyAuthorizeNvCmd),
    /// Require authorization with the authValue of the authorized entity.
    ///
    /// Wraps TPM2_PolicyAuthValue.
    Policyauthvalue(cmd::policyauthvalue::PolicyAuthValueCmd),
    /// Restrict a policy to one TPM command code.
    ///
    /// Wraps TPM2_PolicyCommandCode.
    Policycommandcode(cmd::policycommandcode::PolicyCommandCodeCmd),
    /// Gate a policy on a comparison against TPM clock or counter data.
    ///
    /// Wraps TPM2_PolicyCounterTimer.
    Policycountertimer(cmd::policycountertimer::PolicyCounterTimerCmd),
    /// Bind a policy to a digest of command parameters.
    ///
    /// Wraps TPM2_PolicyCpHash.
    Policycphash(cmd::policycphash::PolicyCpHashCmd),
    /// Bind a policy to an object's duplication target.
    ///
    /// Wraps TPM2_PolicyDuplicationSelect.
    Policyduplicationselect(cmd::policyduplicationselect::PolicyDuplicationSelectCmd),
    /// Return the current digest of a policy session.
    ///
    /// Wraps TPM2_PolicyGetDigest.
    Policygetdigest(cmd::policygetdigest::PolicyGetDigestCmd),
    /// Restrict a policy to selected TPM localities.
    ///
    /// Wraps TPM2_PolicyLocality.
    Policylocality(cmd::policylocality::PolicyLocalityCmd),
    /// Bind a policy to a digest of object names.
    ///
    /// Wraps TPM2_PolicyNameHash.
    Policynamehash(cmd::policynamehash::PolicyNameHashCmd),
    /// Gate a policy on a comparison with NV index contents.
    ///
    /// Wraps TPM2_PolicyNV.
    Policynv(cmd::policynv::PolicyNvCmd),
    /// Gate a policy on whether an NV index has been written.
    ///
    /// Wraps TPM2_PolicyNvWritten.
    Policynvwritten(cmd::policynvwritten::PolicyNvWrittenCmd),
    /// Combine policy alternatives with a logical OR.
    ///
    /// Wraps TPM2_PolicyOR.
    Policyor(cmd::policyor::PolicyOrCmd),
    /// Require plaintext password authorization for the authorized entity.
    ///
    /// Wraps TPM2_PolicyPassword.
    Policypassword(cmd::policypassword::PolicyPasswordCmd),
    /// Gate a policy on selected PCR values.
    ///
    /// Wraps TPM2_PolicyPCR.
    Policypcr(cmd::policypcr::PolicyPcrCmd),
    /// Require asserted physical presence to satisfy a policy.
    ///
    /// Wraps TPM2_PolicyPhysicalPresence.
    Policyphysicalpresence(cmd::policyphysicalpresence::PolicyPhysicalPresenceCmd),
    /// Reset a policy session and its policy digest.
    ///
    /// Wraps TPM2_PolicyRestart.
    Policyrestart(cmd::policyrestart::PolicyRestartCmd),
    /// Authorize a policy assertion using another entity's secret.
    ///
    /// Wraps TPM2_PolicySecret.
    Policysecret(cmd::policysecret::PolicySecretCmd),
    /// Authorize a policy assertion with an external signature.
    ///
    /// Wraps TPM2_PolicySigned.
    Policysigned(cmd::policysigned::PolicySignedCmd),
    /// Bind a policy to an object creation template digest.
    ///
    /// Wraps TPM2_PolicyTemplate.
    Policytemplate(cmd::policytemplate::PolicyTemplateCmd),
    /// Satisfy a policy assertion using a previously issued authorization ticket.
    ///
    /// Wraps TPM2_PolicyTicket.
    Policyticket(cmd::policyticket::PolicyTicketCmd),
    /// Decode and display a marshaled TPM data structure.
    ///
    /// Client-side utility; it does not invoke a TPM command.
    Print(cmd::print::PrintCmd),
    /// Produce a signed attestation over selected PCRs.
    ///
    /// Wraps TPM2_Quote.
    Quote(cmd::quote::QuoteCmd),
    /// Decode a TPM response code into human-readable fields.
    ///
    /// Client-side utility; it does not invoke a TPM command.
    Rcdecode(cmd::rcdecode::RcDecodeCmd),
    /// Return the TPM time, clock, and reset/restart counters.
    ///
    /// Wraps TPM2_ReadClock.
    Readclock(cmd::readclock::ReadClockCmd),
    /// Return the public area and names of a loaded object.
    ///
    /// Wraps TPM2_ReadPublic.
    Readpublic(cmd::readpublic::ReadPublicCmd),
    /// Decrypt or sign-pad data with a loaded RSA private key.
    ///
    /// Wraps TPM2_RSA_Decrypt.
    Rsadecrypt(cmd::rsadecrypt::RsaDecryptCmd),
    /// Encrypt or verify-pad data with a loaded RSA public key.
    ///
    /// Wraps TPM2_RSA_Encrypt.
    Rsaencrypt(cmd::rsaencrypt::RsaEncryptCmd),
    /// Rewrap a duplicated object from one parent to another.
    ///
    /// Wraps TPM2_Rewrap.
    Rewrap(cmd::rewrap::RewrapCmd),
    /// Start TPM self-testing of implemented algorithms.
    ///
    /// Wraps TPM2_SelfTest.
    Selftest(cmd::selftest::SelfTestCmd),
    /// Send a prebuilt TPM command buffer and return its raw response.
    ///
    /// Low-level transport utility; the input buffer determines the TPM command invoked.
    Send(cmd::send::SendCmd),
    /// Complete a hash or HMAC sequence and return its digest and ticket.
    ///
    /// Wraps TPM2_SequenceComplete.
    Sequencecomplete(cmd::sequencecomplete::SequenceCompleteCmd),
    /// Add message data to an active hash or HMAC sequence.
    ///
    /// Wraps TPM2_SequenceUpdate.
    Sequenceupdate(cmd::sequenceupdate::SequenceUpdateCmd),
    /// Modify attributes stored with an ESAPI session context.
    ///
    /// Client-side ESAPI utility; it does not invoke a TPM command.
    Sessionconfig(cmd::sessionconfig::SessionConfigCmd),
    /// Select commands included in the TPM command audit digest.
    ///
    /// Wraps TPM2_SetCommandCodeAuditStatus.
    Setcommandauditstatus(cmd::setcommandauditstatus::SetCommandAuditStatusCmd),
    /// Set the authorization policy for a hierarchy.
    ///
    /// Wraps TPM2_SetPrimaryPolicy.
    Setprimarypolicy(cmd::setprimarypolicy::SetPrimaryPolicyCmd),
    /// Prepare the TPM for an orderly shutdown.
    ///
    /// Wraps TPM2_Shutdown.
    Shutdown(cmd::shutdown::ShutdownCmd),
    /// Sign a caller-provided digest with a loaded key.
    ///
    /// Wraps TPM2_Sign, deprecated since TPM 2.0 Library version 185.
    Sign(cmd::sign::SignCmd),
    /// Start an HMAC, policy, or trial authorization session.
    ///
    /// Wraps TPM2_StartAuthSession.
    Startauthsession(cmd::startauthsession::StartAuthSessionCmd),
    /// Initialize TPM state after power-up or reset.
    ///
    /// Wraps TPM2_Startup.
    Startup(cmd::startup::StartupCmd),
    /// Mix caller-provided entropy into the TPM random-number generator.
    ///
    /// Wraps TPM2_StirRandom.
    Stirrandom(cmd::stirrandom::StirRandomCmd),
    /// Test whether a set of public algorithm parameters is supported.
    ///
    /// Wraps TPM2_TestParms.
    Testparms(cmd::testparms::TestParmsCmd),
    /// Return sensitive data from a loaded sealed object.
    ///
    /// Wraps TPM2_Unseal.
    Unseal(cmd::unseal::UnsealCmd),
    /// Verify a signature over a caller-provided digest with a loaded key.
    ///
    /// Wraps TPM2_VerifySignature, deprecated since TPM 2.0 Library version 185.
    Verifysignature(cmd::verifysignature::VerifySignatureCmd),
    /// Complete a two-phase ECC key exchange with a loaded private key.
    ///
    /// Wraps TPM2_ZGen_2Phase.
    Zgen2phase(cmd::zgen2phase::Zgen2PhaseCmd),
}
