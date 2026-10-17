# Identity storage

Identity fingerprints contain 32 lowercase hexadecimal characters. The public token and underlying key pairs do not change.

New identity files are encrypted before any bytes reach a temporary file. Windows uses current-user DPAPI by default, with UI disabled and application-specific entropy. It does not use machine-wide protection. An explicit `TIG_IDENTITY_PASSPHRASE` selects portable passphrase storage on Windows too. Other platforms prompt without echo, or read that variable for unattended use. Empty passphrases are refused.

The portable version-1 envelope uses Argon2id v19 with fixed RustCrypto 0.5 defaults (19 MiB, two iterations, one lane), a random 16-byte salt, and XChaCha20-Poly1305 with a random 24-byte nonce. Its authenticated context is specific to identity files. Windows version 2 contains the DPAPI envelope.

Existing raw 64-byte files are encrypted and atomically replaced on first successful load, preserving the same public identity. Failed unlocks, malformed envelopes, and failed migrations do not generate a new identity or overwrite the stored file. Secret buffers are zeroized; Unix files retain mode 0600. Reads are bounded to 16 KiB.

DPAPI files require the corresponding Windows credentials. Keep passphrases outside the repository and command arguments. No unencrypted identity backup is created during migration.

Implementation references: [Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [RustCrypto Argon2](https://docs.rs/argon2/0.5.3/argon2/struct.Argon2.html).
