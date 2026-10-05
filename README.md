# asymcrypt

`asymcrypt` lets you encrypt data offline with a key that can't decrypt it afterwards.

It works a lot like [`encpipe`](https://github.com/jedisct1/encpipe). By default, it reads from `stdin` and writes to `stdout`, so file paths are optional. It can also handle inputs of any size.

Under the hood, it uses [AEGIS-128X](https://www.rfc-editor.org/rfc/rfc10032.html), a fast AES-based cipher that also checks that the data hasn't been tampered with. On any CPU with hardware AES support, it runs about as fast as memory can keep up. On top of that, the key exchange is designed to resist quantum computers.

## Why use it

So what's the difference from regular symmetric encryption? Here, the machine doing the encryption only has a public key (an X-Wing key).

Every time you encrypt something, `asymcrypt` creates a new secret just for that file, uses it, and then throws it away. As a result, the machine can't decrypt anything it has encrypted, because it never had the key needed to do so.

To decrypt, you need a separate recovery key (or a password) that you set aside when you first created the keys. That key never has to be on the machine doing the encryption.

This is useful in many situations. For example:

- Backups on a server that could be stolen or hacked one day.
- Logs sent from a machine you don't trust to read its own history.
- Archives written by a service that shouldn't be able to read back what it wrote.
- Drop boxes, where one person encrypts files for someone else.

In short, it fits anywhere you want something that can write data but not read it.

Also, everything works offline. There's no handshake, no server, and nobody to coordinate with.

You create your keys once, with a single local command. After that, the machine can encrypt as much as it wants without ever contacting whoever holds the recovery key. Meanwhile, the recovery key stays wherever you put it, and you only take it out when you actually need to decrypt something.

## Installing

```sh
cargo install asymcrypt
```

## Setting up

First, create a new key pair. Both keys are made locally in one step, with no network access and nothing sent between machines.

```sh
asymcrypt init -o device.key -r recovery.key
```

The recovery key (`recovery.key`) is a 32-byte secret. You can print it, save it on a USB stick, put it in a password manager, or store it however suits you. It's the only thing that can decrypt your files, so it can stay where it is until you need to recover something.

The device key (`device.key`) is the public key. It stays on the machine that encrypts, and nothing ever changes it.

Next, move `recovery.key` somewhere the encrypting machine can't reach, and keep `device.key` on that machine.

Be careful, though: if you lose `recovery.key`, you lose access to every file it was meant to unlock. So keep it safe.

## Encrypting

To encrypt, give `encrypt` the device key and send it any data:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
```

Each run creates a new one-time secret, while the device key itself stays the same.

Once that's done, the machine can no longer read what it just encrypted.

This means you can leave the encrypted file on the same machine, copy it to a NAS, or upload it to a shared place. Either way, the machine never had a way to read it.

## What you get

Since the machine only holds a public key, even an attacker who takes full control of it can't decrypt anything, whether it was encrypted before or after the attack.

The only thing they gain is the ability to encrypt, which they could already do anyway. In other words, the protection comes from the design itself: the secret key is simply never on the machine.

## Decrypting

On any machine that has the recovery key, run:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

## Password mode

If you'd rather remember a password than store a recovery key, use `--password` when setting up:

```sh
asymcrypt init --password -o device.key
```

You'll be asked for a password, then asked to type it again.

In this case, the device key file holds the public key plus a copy of the secret key, encrypted with your password (using Argon2id). To decrypt, you only need the password and the encrypted file:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

So in this mode, the password replaces the recovery key, and there's nothing else to store.

However, if you forget the password, your files are gone for good.

Keep in mind that password mode is less secure than the default mode. Both the device key file and each encrypted file contain the secret key, protected only by your password. Because of this, anyone who gets hold of either one can try to guess the password offline, as many times as they like. Your safety then depends on how strong your password is and on the Argon2 settings.

If you want to use `asymcrypt` in scripts, you can set the `ASYMCRYPT_PASSWORD` environment variable, and it will use that instead of asking.

That said, be careful: other programs running as the same user can usually read your environment variables.

## Input and output

- `-i PATH` reads from `PATH`. If you leave out `-i`, or use `-i -`, it reads from `stdin`. That's the normal way to use it, since it's meant to be part of a pipe.
- `-o PATH` writes to `PATH`. If you leave out `-o`, or use `-o -`, it writes to `stdout`.
- It never overwrites an existing file. If you really want to replace one, add `--force`.

When writing to a file, `asymcrypt` first writes to a temporary file in the same folder. Then, once everything has been written and saved, it renames it to the final name. That way, if something crashes halfway through, you won't end up with a half-written file.

## Key file formats

### Type 0x01: device key (public)

1217 bytes: one type byte, followed by the 1216-byte X-Wing public key.

Since it's a public key, file permissions aren't checked.

### Type 0x02: combined key (password mode)

1310 bytes: one type byte, the 1216-byte public key, the 32-byte encrypted secret key, a 32-byte AEGIS tag, and 29 bytes of Argon2 settings.

Because it contains an encrypted secret, the file must have 0o600 permissions.

### Type 0x03: recovery key (private)

33 bytes: one type byte, followed by the 32-byte X-Wing secret key seed.

This one should be kept offline, and the file must have 0o600 permissions.

All key files are saved as raw binary by default, or as hex text if you add `--hex`.

## Other implementations

There's also a Zig version: [zig-asymcrypt](https://github.com/jedisct1/zig-asymcrypt).
