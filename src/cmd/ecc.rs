// SPDX-License-Identifier: Apache-2.0

use tss_esapi::structures::{EccParameter, EccPoint};

pub(super) fn bytes_to_ecc_point(data: &[u8]) -> anyhow::Result<EccPoint> {
    if data.is_empty() || (data.len() & 1) != 0 {
        anyhow::bail!("ECC point must contain equal, non-empty x and y coordinates");
    }

    let half = data.len() / 2;
    let x = EccParameter::try_from(data[..half].to_vec())
        .map_err(|e| anyhow::anyhow!("invalid ECC x coordinate: {e}"))?;
    let y = EccParameter::try_from(data[half..].to_vec())
        .map_err(|e| anyhow::anyhow!("invalid ECC y coordinate: {e}"))?;
    Ok(EccPoint::new(x, y))
}

pub(super) fn ecc_point_to_bytes(point: &EccPoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.x().len() + point.y().len());
    out.extend_from_slice(point.x().as_bytes());
    out.extend_from_slice(point.y().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_point_round_trips() {
        let encoded = [1, 2, 3, 4];
        let point = bytes_to_ecc_point(&encoded).unwrap();
        assert_eq!(ecc_point_to_bytes(&point), encoded);
    }

    #[test]
    fn ecc_point_requires_equal_non_empty_coordinates() {
        assert!(bytes_to_ecc_point(&[]).is_err());
        assert!(bytes_to_ecc_point(&[1, 2, 3]).is_err());
    }
}
