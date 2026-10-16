//! Identity envelopes. Windows defaults to current-user DPAPI; an explicit
//! passphrase also permits portable files. Other platforms use a passphrase.

use std::io::{self, IsTerminal};
use tig_private::keys::Identity;
use zeroize::Zeroizing;
use super::super::{CliError, Result};

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(value) = std::env::var_os("TIG_IDENTITY_PASSPHRASE") {
        let value = Zeroizing::new(value.into_string().map_err(|_| CliError::msg("identity passphrase must be UTF-8"))?);
        if value.is_empty() { return Err(CliError::msg("identity passphrase must not be empty")); }
        return Ok(value);
    }
    if !io::stdin().is_terminal() {
        return Err(CliError::msg("identity needs a passphrase; run interactively or set TIG_IDENTITY_PASSPHRASE"));
    }
    let value = Zeroizing::new(rpassword::prompt_password("Identity passphrase: ")?);
    if value.is_empty() { return Err(CliError::msg("identity passphrase must not be empty")); }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Confirm identity passphrase: ")?);
        if *again != *value { return Err(CliError::msg("identity passphrases do not match")); }
    }
    Ok(value)
}

pub(super) fn seal(identity: &Identity) -> Result<Vec<u8>> {
    #[cfg(windows)]
    if std::env::var_os("TIG_IDENTITY_PASSPHRASE").is_none() {
        let mut out = b"TIGI\x02".to_vec();
        out.extend_from_slice(&dpapi::transform(&*identity.to_bytes(), false)?);
        return Ok(out);
    }
    Ok(identity.encrypt(passphrase(true)?.as_bytes())?)
}

pub(super) fn open(bytes: &[u8]) -> Result<Identity> {
    if bytes.starts_with(b"TIGI\x01") {
        return Identity::decrypt(bytes, passphrase(false)?.as_bytes())
            .map_err(|_| CliError::msg("cannot unlock identity: wrong passphrase or damaged identity file"));
    }
    #[cfg(windows)]
    if let Some(body) = bytes.strip_prefix(b"TIGI\x02") {
        let plaintext = dpapi::transform(body, true)?;
        let secret = plaintext.as_slice().try_into()
            .map_err(|_| CliError::msg("invalid protected identity length"))?;
        return Ok(Identity::from_bytes(secret));
    }
    Err(CliError::msg("unsupported or damaged protected identity file"))
}

#[cfg(windows)]
mod dpapi {
    use super::*;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    pub(super) fn transform(bytes: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len().try_into().map_err(|_| CliError::msg("protected identity is too large"))?,
            pbData: bytes.as_ptr().cast_mut(),
        };
        let label = tig_core::domain::IDENTITY_WINDOWS_ENTROPY;
        let entropy = CRYPT_INTEGER_BLOB { cbData: label.len() as u32, pbData: label.as_ptr().cast_mut() };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: all input slices live through the call; DPAPI allocates the
        // output, which is copied, zeroed, and released with LocalFree below.
        let success = unsafe {
            if decrypt {
                CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null(),
                    std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null(),
                    std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if success == 0 { return Err(CliError::msg(format!("cannot protect or unlock identity with Windows credentials: {}", io::Error::last_os_error()))); }
        // SAFETY: success guarantees a valid allocation of cbData bytes.
        let result = unsafe {
            let body = if output.cbData == 0 { &mut [] }
                else { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
            let copy = Zeroizing::new(body.to_vec());
            zeroize::Zeroize::zeroize(body);
            LocalFree(output.pbData.cast());
            copy
        };
        Ok(result)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_and_valid_but_empty_payload() {
        let identity = Identity::from_bytes([37; 64]);
        let mut protected = b"TIGI\x02".to_vec();
        protected.extend_from_slice(&dpapi::transform(&*identity.to_bytes(), false).unwrap());
        assert_eq!(open(&protected).unwrap().public(), identity.public());
        let mut empty = b"TIGI\x02".to_vec();
        empty.extend_from_slice(&dpapi::transform(&[], false).unwrap());
        assert!(open(&empty).is_err());
    }
}
