//! # No Chat Reports (NCR) Crypto
//!
//! The cryptography used to generate passwords and encrypted messages
//! exactly as the [No Chat Reports](https://github.com/Aizistral-Studios/No-Chat-Reports) Mod for Minecraft does.
//!
//! # Examples
//!
//! ```
//! use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
//! use ncr_crypto::{decrypt_with_passphrase, decode_and_verify};
//!
//! let passphrase = b"secret";  // Setting in NCR
//! // "Hello, world!" sent as a message in chat:
//! let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
//! let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
//! let ciphertext = b64.decode("q2JCS/M3yMnz+MtXDn4dd6xyqN94Dao=").unwrap();
//!
//! let decrypted = decrypt_with_passphrase(&ciphertext, passphrase);
//! let decoded = decode_and_verify(&decrypted);
//!
//! assert_eq!(decoded, Ok("#%Hello, world!"))
//! ```
//!
//! # How it works
//!
//! From reading the Source Code on Github it becomes clear how the mod does encryption:
//!
//! 1. You set a passphrase like "secret" in the UI
//! 2. The mod uses `PBKDF2_HMAC_SHA1` with a hardcoded salt and 65536 iterations to make your passphrase
//! into a hash of 16 bytes. This process takes the longest
//! 3. An Initialization Vector (IV) is generated from a random nonce value, and used in the encryption that follows
//! 4. The new hash becomes the key used for encrypting any messages you send with `AES-CFB8` encryption
//! 5. The ciphertext that comes from this encryption is appended to the nonce that was generated, and the final message
//! that is sent in Base64 encoding through the chat (note: `"#%"` is added as a prefix to the message before encrypting)
//!
//! Decrypting then is very similar, just in reverse:
//!
//! 1. Decode the message from Base64 into raw bytes
//! 2. Get the nonce from the message and generate the IV again with it
//! 2. Generate the hash from the secret passphrase again, and use it as the key for the AES encryption
//! 3. If the decrypted message starts with `"#%"`, the rest is printed decrypted in the chat

use std::{
    error::Error,
    fmt::Display,
    io::{BufReader, Read},
    num::NonZeroU32,
    str::from_utf8,
};

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::pbkdf2;
use ring::pbkdf2::PBKDF2_HMAC_SHA1;

type Aes128Cfb8Dec = cfb8::Decryptor<aes::Aes128>;
type Aes128Cfb8Enc = cfb8::Encryptor<aes::Aes128>;

/// Content salt for all passphrases ([source](https://github.com/Aizistral-Studios/No-Chat-Reports/blob/c2c60a03544952fe608bd65163cc0b2658e3c032/src/main/java/com/aizistral/nochatreports/encryption/AESEncryption.java#L57-L58))
///
/// Generated as follows:
///
/// ```
/// let mut salt = [0; 16];
/// java_rand::Random::new(1738389128127)
///     .next_bytes(&mut salt);
///
/// assert_eq!(salt, [45, 72, 24, 73, 11, 12, 10, 149, 250, 165, 68, 71, 1, 217, 153, 119]);
/// ```
pub const SALT: [u8; 16] = [
    45, 72, 24, 73, 11, 12, 10, 149, 250, 165, 68, 71, 1, 217, 153, 119,
];

/// Generate a key from a passphrase
///
/// Use `PBKDF2_HMAC_SHA1` with a hardcoded salt and 65536 iterations to hash a passphrase into a 16-byte key
///
/// # Examples
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::generate_key;
///
/// let passphrase = b"secret";
///
/// let key = generate_key(passphrase);
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
///
/// assert_eq!(b64.encode(key), "474esvGYVuN83HpxbK1uFQ==");  // Can be seen in the NCR UI when typing the passphrase
/// ```
pub fn generate_key(passphrase: &[u8]) -> [u8; 16] {
    let mut key = [0; 16];
    pbkdf2::derive(
        PBKDF2_HMAC_SHA1,
        NonZeroU32::new(65536).unwrap(),
        &SALT,
        &passphrase,
        &mut key,
    );

    key
}

/// Encrypt a plaintext message with a given key
///
/// > **Warning**: This function does **not** append `"#%"` to the message before encrypting. NCR automatically does this when sending a message,
/// > so add it if you're planning to send a real message that NCR should recognize
///
/// NCR uses AES-CFB8 for encryption, with a 16-byte key. Generate a key from [`generate_key()`] using a passphrase, or
/// provide the raw bytes to this function. You can also use [`encrypt_with_passphrase()`] as a shorthand for doing both of these things
///
/// # Examples
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::{encrypt, decrypt};
///
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
/// let key = b64.decode("blfrngArk3chG6wzncOZ5A==").unwrap();  // Default key
/// let key = key.try_into().unwrap();
/// let plaintext = b"#%Hello, world!";
///
/// let encrypted = encrypt(plaintext, &key);
/// // Here `encrypted` is something random like [240, 28, 167, ..., 237, 3, 89]
/// let decrypted = decrypt(&encrypted, &key);
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn encrypt(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    // This function is a bit of a mess with Bytes and conversions, but it works ¯\_(ツ)_/¯

    let mut plaintext = Vec::from(plaintext);

    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap(); // Actually uses java.security.SecureRandom, but for generating our nonce this doesn't matter
    let nonce = Bytes::from(Vec::from(nonce)).get_u64();

    let mut iv = [0; 16];
    java_rand::Random::new(nonce).next_bytes(&mut iv);

    Aes128Cfb8Enc::new(key.into(), &iv.into()).encrypt(&mut plaintext);

    let mut ciphertext = BytesMut::with_capacity(8 + plaintext.len());
    ciphertext.put(Bytes::from(Vec::from(nonce.to_be_bytes())));
    ciphertext.put(Bytes::from(plaintext)); // `plaintext` is encrypted at this point

    ciphertext.to_vec()
}

/// Decrypt a ciphertext message with a given key
///
/// NCR uses AES-CFB8 for encryption, with a 16-byte key. Generate a key from [`generate_key()`] using a passphrase, or
/// provide the raw bytes to this function. You can also use [`decrypt_with_passphrase()`] as a shorthand for doing both of these things
///
/// # Examples
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::decrypt;
///
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
/// let key = b64.decode("blfrngArk3chG6wzncOZ5A==").unwrap();  // Default key
/// let ciphertext = b64.decode("NuhaeyIn3WJDHY/W0X++EJKON32pDAA=").unwrap();
///
/// let decrypted = decrypt(&ciphertext, &key.try_into().unwrap());
///
/// assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "#%Hello, world!");
/// ```
pub fn decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut buf_reader = BufReader::new(ciphertext);

    let mut nonce = [0; 8];
    buf_reader.read(&mut nonce).unwrap();
    let nonce = u64::from_be_bytes(nonce);

    let mut encrypted = Vec::new();
    buf_reader.read_to_end(&mut encrypted).unwrap();

    let mut iv = [0; 16];
    java_rand::Random::new(nonce).next_bytes(&mut iv);

    Aes128Cfb8Dec::new(key.into(), &iv.into()).decrypt(&mut encrypted);

    encrypted.to_vec()
}

/// Encrypt a ciphertext message with a given passphrase
///
/// Shorthand for [`generate_key()`] and then [`encrypt()`]
///
/// # Examples
///
/// ```
/// use ncr_crypto::{encrypt_with_passphrase, decrypt_with_passphrase};
///
/// let passphrase = b"secret";
/// let plaintext = b"#%Hello, world!";
///
/// let encrypted = encrypt_with_passphrase(plaintext, passphrase);
/// // Here `encrypted` is something random like [240, 28, 167, ..., 237, 3, 89]
/// let decrypted = decrypt_with_passphrase(&encrypted, passphrase);
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let key = generate_key(passphrase);
    encrypt(plaintext, &key)
}

/// Decrypt a ciphertext message with a given passphrase
///
/// Shorthand for [`generate_key()`] and then [`decrypt()`]
///
/// # Examples
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::decrypt_with_passphrase;
///
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
/// let passphrase = b"secret";
/// let ciphertext = b64.decode("q2JCS/M3yMnz+MtXDn4dd6xyqN94Dao=").unwrap();
///
/// let decrypted = decrypt_with_passphrase(&ciphertext, passphrase);
///
/// assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "#%Hello, world!");
/// ```
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let key = generate_key(passphrase);
    decrypt(ciphertext, &key)
}

#[derive(Debug, Clone, PartialEq)]
pub struct FormatError;

impl Error for FormatError {}
impl Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "string did not start with '#%' or is invalid UTF8")
    }
}

/// Verify if a message could be correctly decrypted
///
/// Decrypted message from NCR are always prefixed with "#%", and contain valid UTF8. This function verifies both of these things
/// and returns a Result containing the decoded `&str` or a `FormatError` in case it is not valid
///
/// # Examples
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::{decode_and_verify, decrypt_with_passphrase};
///
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
/// let passphrase = b"secret";
/// let ciphertext = b64.decode("q2JCS/M3yMnz+MtXDn4dd6xyqN94Dao=").unwrap();
///
/// let decrypted = decrypt_with_passphrase(&ciphertext, passphrase);
/// let decoded = decode_and_verify(&decrypted);
///
/// assert_eq!(decoded, Ok("#%Hello, world!"));
/// ```
///
/// ```
/// use base64::{alphabet::Alphabet, engine::{GeneralPurpose, GeneralPurposeConfig}, Engine};
/// use ncr_crypto::{decode_and_verify, decrypt_with_passphrase, FormatError};
///
/// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\\").unwrap();
/// let b64 = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
/// let passphrase = b"wrong";  // Should be "secret"
/// let ciphertext = b64.decode("q2JCS/M3yMnz+MtXDn4dd6xyqN94Dao=").unwrap();
///
/// let decrypted = decrypt_with_passphrase(&ciphertext, passphrase);
/// let decoded = decode_and_verify(&decrypted);
///
/// assert_eq!(decoded, Err(FormatError));
/// ```
///
/// ```
/// use ncr_crypto::{decode_and_verify, FormatError};
///
/// let bytes = b"Hello, world!";  // Without "#%" prefix
/// let decoded = decode_and_verify(bytes);
///
/// assert_eq!(decoded, Err(FormatError));
/// ```
pub fn decode_and_verify(bytes: &[u8]) -> Result<&str, FormatError> {
    if bytes.len() < 2 || bytes[..2] != [35, 37] {
        // "#%"
        return Err(FormatError);
    }

    match from_utf8(bytes) {
        Ok(decoded) => Ok(decoded),
        Err(_) => Err(FormatError),
    }
}
