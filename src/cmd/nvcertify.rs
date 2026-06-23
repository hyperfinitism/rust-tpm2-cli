// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::abstraction::nv::max_nv_buffer_size;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{
    ContextSource, load_key_from_source, load_nv_index, nv_auth_from_entity, set_nv_auth,
};
use crate::parse::{self, NvAuthEntity, parse_context_source};
use crate::session::load_optional_auth_session;
#[derive(Parser)]
pub struct NvCertifyCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signing-key-context", value_parser = parse_context_source)]
    pub signing_key_context: ContextSource,

    /// NV index to certify (hex, e.g. 0x01000001)
    #[arg(short = 'i', long = "nv-index", value_parser = parse::parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'c', long = "nv-auth-hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub nv_auth_hierarchy: NvAuthEntity,

    /// Authorization value for the signing key
    #[arg(short = 'P', long = "signing-key-auth", value_parser = parse::parse_auth)]
    pub signing_key_auth: Option<Auth>,

    /// Authorization value for the NV index
    #[arg(short = 'p', long = "nv-auth", value_parser = parse::parse_auth)]
    pub nv_auth: Option<Auth>,

    /// Hash algorithm for the signature
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// Size of data to certify (default: remaining data capped to the TPM NV buffer limit)
    #[arg(short = 's', long = "size")]
    pub size: Option<u16>,

    /// Offset within the NV index
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

    /// Session context file for signing key authorization
    #[arg(long = "signing-session")]
    pub signing_session: Option<PathBuf>,

    /// Session context file for NV authorization
    #[arg(long = "nv-session")]
    pub nv_session: Option<PathBuf>,
}

impl NvCertifyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let sign_handle = load_key_from_source(&mut ctx, &self.signing_key_context)?;

        let nv_handle = load_nv_index(&mut ctx, self.nv_index)?;

        let nv_auth = nv_auth_from_entity(self.nv_auth_hierarchy, nv_handle);

        if let Some(ref auth) = self.signing_key_auth {
            ctx.tr_set_auth(sign_handle.into(), auth.clone())
                .context("failed to set signing key authorization")?;
        }
        if let Some(ref auth) = self.nv_auth {
            set_nv_auth(&mut ctx, nv_auth, auth.clone())?;
        }

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        let scheme = self.scheme.with_hash(self.hash_algorithm);
        let (nv_public, _) = ctx
            .execute_without_session(|ctx| ctx.nv_read_public(nv_handle))
            .context("TPM2_NV_ReadPublic failed")?;
        let max_size = max_nv_buffer_size(&mut ctx).context("reading TPM NV buffer limit")?;
        let size = nv_certify_size(nv_public.data_size(), self.offset, self.size, max_size)?;

        let signing_session =
            load_optional_auth_session(&mut ctx, self.signing_session.as_deref())?;
        let nv_session = load_optional_auth_session(&mut ctx, self.nv_session.as_deref())?;
        let (attest, signature) = ctx
            .execute_with_sessions((Some(signing_session), Some(nv_session), None), |ctx| {
                ctx.nv_certify(
                    sign_handle,
                    nv_auth,
                    nv_handle,
                    qualifying_data,
                    scheme,
                    size,
                    self.offset,
                )
            })
            .context("TPM2_NV_Certify failed")?;

        if let Some(ref path) = self.attestation {
            let bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, bytes)
                .with_context(|| format!("writing attestation to {}", path.display()))?;
            info!("attestation saved to {}", path.display());
        }
        if let Some(ref path) = self.signature {
            let bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        info!("NV certify succeeded");
        Ok(())
    }
}

fn nv_certify_size(
    index_size: usize,
    offset: u16,
    requested_size: Option<u16>,
    max_size: usize,
) -> anyhow::Result<u16> {
    let remaining = index_size
        .checked_sub(usize::from(offset))
        .ok_or_else(|| anyhow::anyhow!("NV certify offset exceeds the index size"))?;

    match requested_size {
        Some(size) if usize::from(size) > remaining => {
            anyhow::bail!("NV certify size exceeds the remaining index data")
        }
        Some(size) if usize::from(size) > max_size => {
            anyhow::bail!("NV certify size exceeds the TPM NV buffer limit of {max_size} bytes")
        }
        Some(size) => Ok(size),
        None => u16::try_from(remaining.min(max_size)).context("NV certify size exceeds u16"),
    }
}

#[cfg(test)]
mod tests {
    use super::nv_certify_size;

    #[test]
    fn default_size_is_capped_to_nv_buffer_limit() {
        assert_eq!(nv_certify_size(2048, 0, None, 1024).unwrap(), 1024);
    }

    #[test]
    fn explicit_size_must_fit_remaining_data_and_nv_buffer() {
        assert!(nv_certify_size(2048, 1024, Some(1025), 2048).is_err());
        assert!(nv_certify_size(2048, 0, Some(1025), 1024).is_err());
        assert_eq!(nv_certify_size(2048, 1024, Some(1024), 1024).unwrap(), 1024);
    }
}
