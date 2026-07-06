# flamberge — User Guide

A friendly, start-from-zero guide to removing DRM from ebooks you own.

If you have never heard the term "DRM" before, start at the top and read
straight through. If you already know the basics and just want the commands for
your store, jump to [Part 3 — Walkthroughs by store](#part-3--walkthroughs-by-store).

> **One rule, up front.** Only use flamberge on books you actually bought (or
> otherwise have the right to), and only where removing DRM for personal use is
> lawful where you live. This guide assumes that's your situation.

**Contents**

- [Part 1 — Understanding the basics](#part-1--understanding-the-basics)
  - [What is DRM?](#what-is-drm)
  - [What is a "key", and why do you already have one?](#what-is-a-key-and-why-do-you-already-have-one)
  - [Is this legal? Is it safe?](#is-this-legal-is-it-safe)
  - [The mental model](#the-mental-model)
- [Part 2 — Getting started](#part-2--getting-started)
  - [Install flamberge](#install-flamberge)
  - [Anatomy of a decrypt command](#anatomy-of-a-decrypt-command)
  - [Where does the output go?](#where-does-the-output-go)
- [Part 3 — Walkthroughs by store](#part-3--walkthroughs-by-store)
  - [Kindle (Amazon)](#kindle-amazon)
  - [Kobo](#kobo)
  - [Adobe & library books (EPUB and PDF)](#adobe--library-books-epub-and-pdf)
  - [Barnes & Noble](#barnes--noble)
  - [eReader / Fictionwise](#ereader--fictionwise)
- [Part 4 — Going further](#part-4--going-further)
  - [Decrypting a whole folder at once](#decrypting-a-whole-folder-at-once)
  - [Letting flamberge find your keys for you](#letting-flamberge-find-your-keys-for-you)
  - [Troubleshooting](#troubleshooting)
  - [Platform support at a glance](#platform-support-at-a-glance)
  - [For the curious: how it actually works](#for-the-curious-how-it-actually-works)

---

## Part 1 — Understanding the basics

### What is DRM?

**DRM** stands for **Digital Rights Management**. It's a lock that stores put on
the ebooks they sell, so that a book you buy from one place will only open in
that company's app, on devices tied to your account.

You have probably felt this without knowing its name:

- You buy a book on your Kindle, but you can't open that file in a different
  reading app.
- You borrow an ebook from your library, and it "expires" or refuses to open
  outside the library's app.
- You switch from a Kindle to a Kobo (or vice versa) and discover your old books
  won't come with you.

That's DRM. The book file on your disk is **scrambled** (encrypted). Without the
right to unscramble it, it's just noise to any program that isn't the store's
official app.

**flamberge unscrambles it** — turning a locked book you own into a plain,
standard file (`.epub`, `.mobi`, `.pdf`, …) that any reader can open, that you
can back up, and that will still open years from now even if the store's app is
gone.

### What is a "key", and why do you already have one?

To unscramble the book, you need the **key** — a secret value that the lock was
built around. Here's the important part:

> **You already have the key.** It isn't something you buy or crack. It's a
> secret that was created when you set up your reading device or app, and it's
> sitting on your own computer or device right now.

Depending on the store, "your key" is derived from something like:

- your **Kindle device's serial number**, or your Amazon account files;
- your **Kobo account** and the device you registered;
- the **Adobe ID** you activated a reading app with (this is what most library
  and independent ebooks use);
- your **name and the credit-card number** you bought with (for older Barnes &
  Noble and eReader books).

flamberge's job is really two jobs: **(1) get your key**, and **(2) use it to
unlock the book**. Sometimes you hand it the key directly; more often, flamberge
can dig the key out of your own device or app files for you. Part 3 shows both,
store by store.

### Is this legal? Is it safe?

**On the legal side:** in many places, making a personal-use copy of media you
bought — including removing DRM to do so — is fine, while sharing or selling
those copies is not. But the rules genuinely differ from country to country.
flamberge doesn't decide this for you. Use it on your own books, for your own
use, where that's permitted. If you're unsure, check your local law.

**On the safety side, flamberge is deliberately boring and private:**

- **Nothing is uploaded.** flamberge is a command-line tool that runs entirely
  on your machine. It doesn't phone home, doesn't need an account, and doesn't
  send your books or keys anywhere.
- **Your original file is never modified.** flamberge always writes a **new**
  file next to the original (see [output](#where-does-the-output-go)); if
  anything goes wrong you still have the book you started with.
- **It's open and auditable.** The whole thing is open-source Rust; the exact
  cryptography for each store is written up in
  [`DEDRM_SCHEMES.md`](DEDRM_SCHEMES.md).

### The mental model

Keep this one picture in your head and the rest of the guide will make sense:

```
   locked book file   +   your key   ─────►   plain book file
   (from the store)        (from your             (opens anywhere)
                            device/account)
```

Everything below is just: *figure out where your key is for a given store, then
point flamberge at the book and the key.*

---

## Part 2 — Getting started

### Install flamberge

flamberge is a single, self-contained program. The [README](../README.md#install)
has the full list of package managers; the quickest options:

```sh
# macOS / Linux, if you have Rust installed:
cargo install flamberge

# …or download a pre-built binary for your platform from the Releases page and
# put it on your PATH:
#   https://github.com/kessriga/flamberge/releases
```

Check it's working:

```sh
flamberge --version
flamberge --help
```

If those print something sensible, you're ready.

### Anatomy of a decrypt command

Almost everything you do uses the `decrypt` command. It looks like this:

```sh
flamberge decrypt  <the book file>  <how to find your key>
```

For example, unlocking a Kindle book using your device's serial number:

```sh
flamberge decrypt my-book.azw --serial B001234567890123
#                 └── the book   └── the key (your Kindle serial)
```

You don't have to know which DRM "scheme" a book uses. flamberge picks the right
one automatically from the file's extension (`.azw`, `.epub`, `.pdb`, …) and
then tries the keys you gave it until one fits.

### Where does the output go?

By default, flamberge writes the unlocked book **right next to the original**,
with `_nodrm` added to the name:

```
my-book.azw   ─►   my-book_nodrm.mobi
```

Your original `my-book.azw` is left untouched. To choose the output name or
folder yourself:

```sh
flamberge decrypt my-book.azw --serial B001234567890123 --output ~/Books/my-book.mobi
```

> **Tip:** the output extension can differ from the input — a Kindle `.azw`
> comes out as a standard `.mobi`, a Kobo `.kepub.epub` comes out as a plain
> `.epub`, and so on. That's expected; the new file is the unlocked, standard
> version.

---

## Part 3 — Walkthroughs by store

Find the store your book came from below. Each walkthrough follows the same
shape: **what your book looks like → how to get your key → the command → what
you get out.**

### Kindle (Amazon)

**Your books look like:** `.azw`, `.azw1`, `.azw3`, `.mobi`, `.prc`, or a
`.kfx-zip`, usually downloaded via *"Download & transfer via USB"* from Amazon,
or copied off a Kindle device.

**Your key** comes from your Amazon account/device. flamberge can work from
several sources, easiest first:

1. **A Kindle e-ink device's serial number.** On the device, *Settings → Device
   Info* shows a serial that starts with a `B`. That serial *is* your key:

   ```sh
   flamberge decrypt book.azw --serial B001234567890123
   ```

   You can pass `--serial` more than once if you have several devices.

2. **The Kindle desktop app's account files.** If you read with the Kindle app
   on this computer, flamberge can decode its key database. Point it at a `.k4i`
   file, or let `--auto-keys` find it (see
   [Part 4](#letting-flamberge-find-your-keys-for-you)):

   ```sh
   flamberge decrypt book.azw --k4i my-kindle-key.k4i
   ```

3. **An Android backup.** From an Android phone/tablet with the Kindle app, an
   `adb backup` (`backup.ab`), an `AmazonSecureStorage.xml`, or a
   `map_data_storage.db` can be mined for your device serials:

   ```sh
   flamberge decrypt book.azw --android backup.ab
   ```

**What you get:** a standard `.mobi` (or repackaged `.tpz` / `.kfx-zip` for the
Topaz and KFX formats) that opens in Calibre, Kindle, and other readers.

> If you'd like to see the raw key values first, `flamberge keys kindle --k4i
> my-kindle-key.k4i` prints what it decoded without decrypting a book.

### Kobo

**Your books look like:** `.kepub.epub`, either sitting on a Kobo e-reader or in
the Kobo desktop app's library.

**Your key** comes from your Kobo account, and the per-book unlock data lives in
Kobo's **library database** (a file called `KoboReader.sqlite` on a device, or
`Kobo.sqlite` in the desktop app) — *not* inside the book file. So Kobo needs
one extra ingredient: point flamberge at that database.

The simplest path is to let flamberge discover everything from this computer /
your plugged-in Kobo:

```sh
flamberge decrypt book.kepub.epub --auto-keys
```

Or do it explicitly — derive your key with `keys kobo`, and pass the database:

```sh
flamberge keys kobo                       # shows your candidate Kobo user key(s)
flamberge decrypt book.kepub.epub --kobo-db KoboReader.sqlite
```

If the database lists more than one book, add `--kobo-volumeid <id>` to pick
which one; with a single book it's inferred automatically.

**What you get:** a plain `.epub`.

### Adobe & library books (EPUB and PDF)

This is the big one for **library loans, indie bookshops, and Google Play**
books — most non-Amazon, non-Kobo ebooks use **Adobe DRM** (its technical name
is *ADEPT*). If you read these with **Adobe Digital Editions**, this is you.

**Your books look like:** `.epub` or `.pdf` files that only open after you
"authorize" Adobe Digital Editions with an **Adobe ID**.

**Your key** is the private license key created when you activated Adobe Digital
Editions on this computer. flamberge reads it from Adobe's own `activation.dat`
file. On macOS this is fully automatic:

```sh
flamberge keys adobe            # extract your Adobe key (macOS)
# …or just let decrypt do it in one step:
flamberge decrypt book.epub --auto-keys
flamberge decrypt book.pdf  --auto-keys
```

If you've already exported your Adobe key as a `.der` file (for example with
another tool), you can hand it over directly:

```sh
flamberge decrypt book.epub --adept-key adobekey.der
```

**What you get:** a plain `.epub` or `.pdf`.

> **Platform note:** extracting the Adobe key automatically works on **macOS**
> today. On **Windows**, the key is sealed by the OS in a way that can't be read
> outside your Windows profile, so you'll need to export it to a `.der` on the
> Windows machine and pass it with `--adept-key`. The decryption itself works
> everywhere.

### Barnes & Noble

**Your books look like:** `.epub` or `.pdf` files from the **Nook** store
(older, non-Kindle-format purchases).

**Your key** for these older B&N books is derived from **your name and the
credit-card number** you bought with. Generate it once:

```sh
flamberge keys ignoble --name "Jane Q. Reader" --cc "1234 5678 9012 3456"
```

That prints your B&N user key. Then decrypt with it:

```sh
flamberge decrypt book.epub --bandn-key <the key it printed>
```

**What you get:** a plain `.epub` or `.pdf`.

### eReader / Fictionwise

**Your books look like:** Palm `.pdb` files from the old **eReader /
Fictionwise** store.

**Your key**, like B&N above, comes from **your name and credit-card number**:

```sh
flamberge keys ereader --name "Jane Q. Reader" --cc "4111 1111 1111 1111"
```

Then:

```sh
flamberge decrypt book.pdb --ereader-key <the key it printed>
```

**What you get:** a `.pmlz` — a small zip containing the book as PML markup plus
its images (the native eReader format that Calibre can import).

---

## Part 4 — Going further

### Decrypting a whole folder at once

Point `decrypt` at several files or an entire directory and it will process them
in a batch, printing an `OK` / `SKIP` / `FAIL` line for each:

```sh
flamberge decrypt ~/Books --output-dir ~/Books/nodrm --auto-keys
```

Files it doesn't recognize are **skipped**, not treated as errors. The command's
exit code is non-zero only if a book it *tried* to decrypt actually failed, so
it's safe to drop a mixed folder on it.

### Letting flamberge find your keys for you

`--auto-keys` tells flamberge to look for your local Adobe, Kobo, and Kindle
keys on this computer *before* it starts decrypting, and add whatever it finds to
the set of keys it tries:

```sh
flamberge decrypt book.epub --auto-keys
```

Each source is best-effort — if one isn't available, flamberge prints a warning
and carries on rather than failing. This is the easiest way to decrypt Adobe and
Kobo books on the machine you actually read them on.

### Troubleshooting

**"No valid key" / the book won't decrypt.**
flamberge tried every key you gave it and none unlocked the book. Usually this
means the right key isn't in the set yet:

- Make sure the key belongs to the **same account/device** the book was bought
  or downloaded for. A book from one Kindle won't open with another Kindle's
  serial.
- Add more candidates: pass every device `--serial` you own, add `--auto-keys`,
  or supply the store-specific file (`--k4i`, `--adept-key`, `--kobo-db`).
- For Kobo, remember the `--kobo-db` (or `--auto-keys`) is **required** — the
  key material lives in the library database, not the book.

**"SKIP" in a batch run.**
That file's extension didn't match any scheme flamberge handles, so it was left
alone. This is normal for cover images, already-decrypted books, and other
non-DRM files mixed into a folder.

**A Windows Adobe or Kindle key won't extract.**
Some keys are sealed by Windows in a way that can only be read inside your own
Windows profile, so flamberge can't gather them offline. Export the key on the
Windows machine and pass it directly (e.g. `--adept-key adobekey.der`). The
decryption still runs on any platform.

### Platform support at a glance

Decryption itself is pure Rust and runs on **Linux, macOS, and Windows** for
every store. What differs by platform is only the *automatic key extraction*
that reads another app's local files:

| Getting your key | Linux | macOS | Windows |
|---|:---:|:---:|:---:|
| Kindle serial / generated keys (you supply them) | ✅ | ✅ | ✅ |
| Kindle `.k4i` / `.kinf` / Android artifact (decode a file) | ✅ | ✅ | ✅ |
| Kindle automatic on-host gathering | — | — | — |
| Adobe `activation.dat` (automatic) | — | ✅ | ⛔ export to `.der` instead |
| Kobo device / desktop DB + network-card IDs | ✅ | ✅ | ✅ |
| B&N / eReader key generators (name + card) | ✅ | ✅ | ✅ |

✅ works · — not applicable · ⛔ can't be done offline (use the manual export)

### For the curious: how it actually works

flamberge is a from-scratch Rust reimplementation of the well-known
[DeDRM_tools](https://github.com/apprenticeharper/DeDRM_tools) Calibre plugins.
It picks a **scheme** by file extension (and, for Kindle files, magic bytes),
then tries each candidate key, falling through to the next scheme if a file
isn't what its extension suggested.

Every store maps to a documented scheme:

| Store (this guide) | Scheme name (the code & spec) | Input → output |
|---|---|---|
| Kindle | Mobipocket / Topaz / KFX | `.azw` `.mobi` `.prc` / `.azw1` `.tpz` / `.kfx-zip` → `.mobi` / `.tpz` / `.kfx-zip` |
| Adobe & library | ADEPT | `.epub` → `.epub`, `.pdf` → `.pdf` |
| Barnes & Noble | Ignoble | `.epub` → `.epub`, `.pdf` → `.pdf` |
| eReader | eReader | `.pdb` → `.pmlz` |
| Kobo | Kobo KEPUB | `.kepub.epub` → `.epub` |

If you want the byte-level details — offsets, constants, key derivation for each
scheme — they're all in [`DEDRM_SCHEMES.md`](DEDRM_SCHEMES.md).
