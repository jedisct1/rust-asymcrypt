# asymcrypt

A forward-secure encryption tool.

It works like `encpipe`: input defaults to stdin, output defaults to stdout, can process arbitrary large inputs ; file paths are optional.

What makes it different from a plain symmetric encryption system is that the key on the encrypting machine moves forward on every encryption. Once a message has been written, the host that produced it can no longer decrypt it, nor anything it produced before.

Decryption requires a separate key (or a password) that was set aside when the keys were generated and that never has to live on the encrypting host.

This shape fits a lot of situations: backups on a host that might later be stolen or compromised, log shipping from a machine you don't fully trust to read its own history, append-only archives written by a service that should not be able to look back at what it wrote, drop boxes where one party encrypts to another, and so on. Anywhere you want a writer that cannot also be a reader, this tool applies.

The whole thing runs offline. There is no handshake, no server, no per-message coordination with anyone. You generate a pair of keys once, in a single local command, and from then on the encrypting host can produce as many ciphertexts as it likes without ever talking to the holder of the recovery key. The recovery key sits alone, wherever you decided to put it, and is only consulted when something actually needs to be decrypted.

## Installing

```sh
cargo install asymcrypt
```

## Setting up

You start by creating a fresh pair of keys. Both keys are produced locally in one shot, with no network involved and no exchange between machines.

The recovery key is the one you need to keep offline. Print it, write it to a USB stick, store it in a password manager, whatever fits your threat model. It is the only thing that can ever decrypt a ciphertext, and it never has to leave the place you stored it until you actually need to recover something.

The current key lives on the encrypting host. It can encrypt an unbounded number of inputs on its own, and it is rotated automatically after each one.

```sh
asymcrypt init -o current.key -r recovery.key
```

Move `recovery.key` somewhere the encrypting host cannot reach, and keep `current.key` on the host.

If you ever lose `recovery.key`, every ciphertext ever produced becomes unrecoverable, so treat it accordingly.

## Encrypting

Point `encrypt` at the on-device key and feed it any stream:

```sh
tar c /etc | asymcrypt encrypt -k current.key -o etc.asym
```

Every encryption advances `current.key` by one step before any ciphertext is written.

From then on, the host cannot decrypt what it just produced.

The encrypted output can sit on the same machine, on a NAS, or be uploaded somewhere shared; the host has already lost the ability to read it.

## What forward security does and does not give you

The chain only moves in one direction. Past ciphertexts are safe from anyone who captures the on-device key later, because the material that produced them has already been overwritten and is not recoverable from the current state.

Future ciphertexts are a different matter. An attacker who walks away with the on-device key at some point in time can rotate the chain forward exactly the same way the legitimate host does, and decrypt everything produced from that point on, until the key is rotated out of their reach (for example by reinitializing on a clean host with a fresh key derived from the recovery secret).

In other words: this protects history, not the future. If you suspect the on-device key has leaked, treat every ciphertext written after the leak as readable by the attacker.

## Recovering

Anywhere with the offline recovery key:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

`decrypt` walks the key chain forward from the recovery key until it lines up with the ciphertext, so it does not matter how many times the host has rotated since the file was written.

## Password mode

If you would rather remember a passphrase than store a recovery key, set things up with `--password`:

```sh
asymcrypt init --password -o current.key
```

You will be prompted for a password and then for a confirmation. The on-device file is still rotated on every encryption, but recovery only needs the password and the ciphertext:

```sh
tar c /etc | asymcrypt encrypt -k current.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

The password is the recovery secret in this mode, so there is no separate recovery key to store.

If you forget the password, the ciphertexts are gone.

If you want to script things, set `ASYMCRYPT_PASSWORD` in the environment and `asymcrypt` will use that instead of prompting.

Be careful: anything in the environment is generally readable by other processes running as the same user.

## Input and output

- `-i PATH` reads from `PATH`. Without `-i`, or with `-i -`, `asymcrypt` reads stdin. This is the usual case — encryption is meant to sit in a pipe.
- `-o PATH` writes to `PATH`. Without `-o`, or with `-o -`, output goes to stdout.
- File output never overwrites an existing path. Pass `--force` if you really mean to clobber it.

File output is staged in a temporary file in the destination directory and renamed into place only after the whole stream has been written and flushed. A crash mid-write leaves no partial file behind.

## Key file permissions

`asymcrypt` refuses to read a key file that is group- or world-readable, so a
stray `chmod` does not silently expose your keys. If you really want to
keep a permissive mode (because the file lives on a shared filesystem you
trust, for example), pass `--insecure-perms`. The recommended mode is
`chmod 600`.
