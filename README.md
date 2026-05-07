# asymcrypt

`asymcrypt`: encrypt anything offline with a key that cannot decrypt what it just wrote.

It works like [`encpipe`](https://github.com/jedisct1/encpipe): input defaults to `stdin`, output defaults to `stdout`, can process arbitrary large inputs ; file paths are optional.

Encryption is authenticated, fast, post-quantum resistant, etc. The underlying cipher is [AEGIS-128X](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/), a parallel AES-based AEAD that runs at memory speed on anything with hardware AES support.

What makes it different from a plain symmetric encryption system is that the encrypting host holds only a public ML-KEM-768 encapsulation key. Each encryption performs a fresh KEM encapsulation, producing a per-file shared secret that the host immediately forgets. The host literally cannot decrypt anything it produces: it never held the decapsulation key in the first place.

Decryption requires a separate decapsulation seed (or a password) that was set aside when the keys were generated. It never has to live on the encrypting host.

This shape fits a lot of situations: backups on a host that might later be stolen or compromised, log shipping from a machine you don't fully trust to read its own history, append-only archives written by a service that should not be able to look back at what it wrote, drop boxes where one party encrypts to another, and so on.

Anywhere you want a writer that cannot also be a reader, this tool applies.

The whole thing runs offline. There is no handshake, no server, no per-message coordination with anyone.

You generate a pair of keys once, in a single local command, and from then on the encrypting host can produce as many ciphertexts as it likes without ever talking to the holder of the recovery key. The recovery key sits alone, wherever you decided to put it, and is only consulted when something actually needs to be decrypted.

## Installing

```sh
cargo install asymcrypt
```

## Setting up

You start by creating a fresh ML-KEM-768 key pair. Both keys are produced locally in one shot, with no network involved and no exchange between machines.

The recovery key is a 64-byte decapsulation seed. Print it, write it to a USB stick, store it in a password manager, whatever fits your threat model. It is the only thing that can ever decrypt the ciphertexts, and it never has to leave the place you stored it until you actually need to recover something.

The device key is the public encapsulation key. It lives on the encrypting host and is never modified by any operation.

```sh
asymcrypt init -o device.key -r recovery.key
```

Move `recovery.key` somewhere the encrypting host cannot reach, and keep `device.key` on the host.

If you ever lose `recovery.key`, every ciphertext ever produced becomes unrecoverable, so treat it accordingly.

## Encrypting

Point `encrypt` at the on-device key and feed it any stream:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
```

Each encryption performs a fresh ML-KEM encapsulation. The device key is a public key and is never modified.

From then on, the host cannot decrypt what it just produced.

The encrypted output can sit on the same machine, on a NAS, or be uploaded somewhere shared; the host never had the ability to read it.

## What this gives you

The device holds only a public encapsulation key. Even if the device is fully compromised, the attacker gains nothing useful for decrypting any ciphertext, past or future. They only get the ability to encrypt, which they could already do since they have the device. Security is structural: the device never holds the decapsulation key, period.

## Recovering

Anywhere with the offline recovery key:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

## Password mode

If you would rather remember a passphrase than store a recovery key, set things up with `--password`:

```sh
asymcrypt init --password -o device.key
```

You will be prompted for a password and then for a confirmation. The device file now contains the public encapsulation key plus the decapsulation seed encrypted under an Argon2id-derived key. Recovery only needs the password and the ciphertext:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

The password is the recovery secret in this mode, so there is no separate recovery key to store.

If you forget the password, the ciphertexts are gone.

Password mode has different security properties than public-key mode. The device key file and every ciphertext header contain the decapsulation seed encrypted under the password. If either is stolen, an attacker can mount an offline password-guessing attack. Security reduces to password strength and Argon2 cost parameters.

If you want to script things, set `ASYMCRYPT_PASSWORD` in the environment and `asymcrypt` will use that instead of prompting.

Be careful: anything in the environment is generally readable by other processes running as the same user.

## Input and output

- `-i PATH` reads from `PATH`. Without `-i`, or with `-i -`, `asymcrypt` reads `stdin`. This is the usual case -- encryption is meant to sit in a pipe.
- `-o PATH` writes to `PATH`. Without `-o`, or with `-o -`, output goes to `stdout`.
- File output never overwrites an existing path. Pass `--force` if you really mean to clobber it.

File output is staged in a temporary file in the destination directory and renamed into place only after the whole stream has been written and flushed. A crash mid-write leaves no partial file behind.

## Key file formats

### Type 0x01 -- Encapsulation key (device, public)

1185 bytes: one type byte plus the 1184-byte ML-KEM-768 encapsulation key. This is a public key. Permission enforcement is skipped.

### Type 0x02 -- Composite key (password mode)

1310 bytes: type byte, 1184-byte encapsulation key, 64-byte encrypted decapsulation seed, 32-byte AEGIS tag, and 29 bytes of Argon2 parameters. Contains an encrypted secret; 0o600 permissions are enforced.

### Type 0x03 -- Decapsulation seed (recovery, private)

65 bytes: one type byte plus the 64-byte ML-KEM-768 decapsulation key seed. Must be kept offline. 0o600 permissions are enforced.

All key files can be written as raw binary (default) or ASCII hex (`--hex`).

## Other implementations

A Zig implementation is available at [zig-asymcrypt](https://github.com/jedisct1/zig-asymcrypt).
