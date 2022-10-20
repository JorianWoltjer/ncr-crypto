# No Chat Reports (NCR) Crypto

The cryptography used to generate passwords and encrypted messages
exactly as the [No Chat Reports](https://github.com/Aizistral-Studios/No-Chat-Reports) Mod for Minecraft does.

# Example

```Rust
use ncr_encryption::{decrypt_with_passphrase, decode_and_verify};

let passphrase = b"secret";  // Setting in NCR
// "Hello, world!" sent as a message in chat:
let ciphertext = base64::decode("q2JCS/M3yMnz+MtXDn4dd6xyqN94Dao=").unwrap();

let decrypted = decrypt_with_passphrase(&ciphertext, passphrase);
let decoded = decode_and_verify(&decrypted);

assert_eq!(decoded, Ok("#%Hello, world!"))
```

# How it works

From reading the Source Code on Github it becomes clear how the mod does encryption:

1. You set a passphrase like "secret" in the UI
2. The mod uses `PBKDF2WithHmacSHA1` with a hardcoded salt and 65536 iterations to make your passphrase 
into a hash of 16 bytes. This process takes the longest
3. An Initialization Vector (IV) is generated from a random nonce value, and used in the encryption that follows
4. The new hash becomes the key used for encrypting any messages you send with `AES-CFB8` encryption
5. The ciphertext that comes from this encryption is appended to the nonce that was generated, and the final message 
that is sent in Base64 encoding through the chat (note: `"#%"` is added as a prefix to the message before encrypting)

Decrypting then is very similar, just in reverse:

1. Decode the message from Base64 into raw bytes
2. Get the nonce from the message and generate the IV again with it
2. Generate the hash from the secret passphrase again, and use it as the key for the AES encryption
3. If the decrypted message starts with `"#%"`, the rest is printed decrypted in the chat
