# asymcrypt

Encrypt stuff offline, with a key that can't decrypt it afterwards.

If you've used [`encpipe`](https://github.com/jedisct1/encpipe), you already know how it works. It reads from `stdin`, writes to `stdout`, and doesn't care how big the input is. You can pass file names too, but you don't have to.

The cipher is [AEGIS-128X](https://www.rfc-editor.org/rfc/rfc10032.html). It's fast (on any CPU with AES instructions, it basically goes as fast as your memory), and it also catches any tampering with the data. On top of that, the way keys are exchanged is ready for quantum computers.

## But why?

With regular encryption, the key that encrypts your data can also decrypt it. Here, that's not the case.

The machine doing the encryption only gets a public key (an X-Wing key). Every time it encrypts something, a brand new secret is created for that file, used, and then forgotten. And since the machine never has the private key, it simply can't read back what it wrote.

To decrypt, you need the recovery key (or a password) that you put aside when you created the keys. That key never needs to be on the machine doing the encryption.

Where is this handy? A few examples:

- Backups on a server that might get stolen or hacked one day.
- Logs coming from a machine you don't really trust to read its own history.
- Archives written by a service that shouldn't be able to look back at what it wrote.
- Drop boxes, where someone encrypts files for someone else.

Basically, anytime you want something that can write but not read.

And it's all offline. No handshake, no server, nobody to talk to.

You create the keys once, with a single command. After that, the machine can encrypt as much as it wants without ever contacting whoever has the recovery key. The recovery key just sits wherever you put it, until you actually need to decrypt something.

## Installing

```sh
cargo install asymcrypt
```

## Setting up

First, create a key pair. Everything happens locally, in one step. No network, nothing sent anywhere.

```sh
asymcrypt init -o device.key -r recovery.key
```

You now have two files.

`recovery.key` is a 32-byte secret, and it's the one to keep offline. Print it, put it on a USB stick, save it in your password manager, whatever works for you. It's the only thing that can decrypt your files, so it can stay there until you need it.

`device.key` is the public key. It goes on the machine that encrypts, and nothing ever changes it.

So, move `recovery.key` somewhere the encrypting machine can't get to, and leave `device.key` where it is.

One warning, though: lose `recovery.key`, and everything encrypted with it is gone. Forever. So don't lose it.

## Encrypting

Give `encrypt` the device key, and pipe whatever you want into it:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
```

Each time, a new one-time secret is created, and the device key doesn't change. And right after that, the machine can't read what it just encrypted.

So you can keep the encrypted file on the same machine, copy it to a NAS, or upload it somewhere. It doesn't matter: the machine never had a way to read it.

## What if the machine gets hacked?

Not much happens, actually. The machine only has a public key, so even someone with full control over it can't decrypt anything, whether it was encrypted before or after.

Sure, they can encrypt new stuff. But they could already do that anyway, since they have the machine. The private key just isn't there, so there's nothing to steal.

## Decrypting

On any machine that has the recovery key:

```sh
asymcrypt decrypt -k recovery.key -i etc.asym | tar x
```

## Password mode

Would you rather remember a password than keep a recovery key around? Then use `--password` when setting up:

```sh
asymcrypt init --password -o device.key
```

You'll be asked for a password, and then asked to type it again.

This time, `device.key` contains the public key, plus the private key encrypted with your password (using Argon2id). To decrypt, all you need is the password and the encrypted file:

```sh
tar c /etc | asymcrypt encrypt -k device.key -o etc.asym
asymcrypt decrypt --password -i etc.asym | tar x
```

In other words, the password is your recovery key now. There's nothing else to keep.

But if you forget the password, your files are gone.

Also, this mode isn't as safe as using a recovery key. Both `device.key` and every encrypted file contain the private key, protected only by your password. So if someone gets hold of either one, they can try guessing the password offline, as many times as they want. How safe you are then comes down to how good your password is, and to the Argon2 settings.

For scripts, you can set the `ASYMCRYPT_PASSWORD` environment variable, and `asymcrypt` will use it instead of asking.

Just keep in mind that other programs running as the same user can usually read your environment variables.

## Input and output

- `-i PATH` reads from `PATH`. Without `-i` (or with `-i -`), it reads from `stdin`. That's how you'd normally use it anyway, in a pipe.
- `-o PATH` writes to `PATH`. Without `-o` (or with `-o -`), it writes to `stdout`.
- It never overwrites an existing file. If that's really what you want, add `--force`.

When writing to a file, `asymcrypt` first writes everything to a temporary file in the same folder, and only renames it once it's all written and saved. So if something crashes halfway, you won't be left with a half-written file.

## Key file formats

### Type 0x01: device key (public)

1217 bytes: one type byte, then the 1216-byte X-Wing public key.

It's a public key, so file permissions aren't checked.

### Type 0x02: combined key (password mode)

1310 bytes: one type byte, the 1216-byte public key, the 32-byte encrypted private key seed, a 32-byte AEGIS tag, and 29 bytes of Argon2 settings.

Since there's an encrypted secret in there, the file must have 0o600 permissions.

### Type 0x03: recovery key (private)

33 bytes: one type byte, then the 32-byte X-Wing private key seed.

Keep this one offline. The file must have 0o600 permissions too.

Key files are saved as raw binary by default. Add `--hex` if you'd rather have them as hex text.

## Other implementations

There's also a Zig version: [zig-asymcrypt](https://github.com/jedisct1/zig-asymcrypt).
