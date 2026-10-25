# Dome Identities

A native FLTK identity and certificate manager for DomeD. It provides shared PEM
identities, OpenPGP through `gpg`, and S/MIME certificates through `gpgsm` in one
window. GnuPG engines remain the owners of their keyrings. PEM imports keep their
existing file paths; generated PEM keys stay in the private shared directory.

The tray icon registers with DomeD's StatusNotifier watcher and exports the
same actions as the universal menu. Closing the window keeps it in the tray
when a watcher is available; File > Quit exits. `--tray` starts hidden and shows
the window if no tray watcher appears. The interface follows DomeD's live
appearance, Unicode BDF font and bitmap scale, and uses FLTK's GPU window.
Wayland appmenu integration is enabled by default. X11 appmenu association is an
explicit `-DDOME_IDENTITIES_ENABLE_X11=ON` build option.

## Build and verify

Build as a regular user against the de-xr FLTK toolkit:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DFLTK_DIR=/opt/fltk-vr/toolkit/share/fltk
cmake --build build
ctest --test-dir build --output-on-failure
python3 tests/ui.py build/dome-identities
# Optional native Wayland QA with an existing nested DomeD build:
DOME_IDENTITIES_COMPOSITOR=../DomeD/target/release/dome-compositor python3 tests/wayland.py
build/dome-identities
```

The core fixture uses disposable catalog and GnuPG directories, an empty test
passphrase and a disabled pinentry. UI QA starts a private Xvfb display and
D-Bus watcher. Native Wayland QA uses a separate nested DomeD compositor,
private runtime directory, fixture keys and disabled session services; it checks
surface/menu association, native prompts, tray restoration and worker shutdown.
These tests read no user identities and change no user keyrings.
`tests/ui.py` needs Python Xlib, Pillow and PyGObject, plus Xvfb and a session bus.
OpenSSL 3, FLTK 1.4.5, GIO, Fontconfig and a C++17 compiler are build dependencies.
`gpg` and `gpgsm` are optional runtime engines; the selected store reports a
missing engine when it cannot start. No dependencies are installed by the build.

## Shared PEM identities

The catalog is `$XDG_DATA_HOME/de-xr/identities/index.json`, falling back to
`~/.local/share/de-xr/identities/index.json`:

```json
{"version":1,"identities":[{"id":"<lowercase SHA-256 certificate DER>",
"name":"Display name","certificate":"/absolute/certificate.pem",
"key":"/absolute/key.pem","address":"optional mailbox@hostname"}]}
```

The directory is mode 0700. The catalog and private key files must be owned by
the current user with owner-only permissions. Generated pairs live under
`<fingerprint>/certificate.pem` and `key.pem`, both mode 0600. Writers share an
owner-only `index.lock` using `flock` and replace the index atomically. Neither
private key bytes nor passphrases are written into the index, settings, UI, or
logs. Certificate/key imports validate the matching unencrypted private key and
certificate dates before publishing a reference. Shared public certificates
must also be owned by the user and not writable by others, matching the browser
reader. Names must be valid UTF-8, nonblank and free of Unicode control
characters, within 256 bytes. Generic Gemini certificates
can be imported too.

Create asks for a name of up to 64 Unicode characters and a mailbox at a DNS
hostname. International DNS names are converted to ASCII IDNA form; mailbox
names use ASCII letters, digits and `._+-`. Numeric IP address forms are refused. It makes a five-year
self-signed RSA-2048/SHA-256 client identity with USER_ID, common name and DNS SAN.
Servo Dome and XNEdit XR can adopt its PEM references; Penguin Mail can explicitly
import its Misfin-compatible identity into its own private store. Creating or
importing a certificate does not register a provider mailbox. Remove drops only
the catalog reference and preserves all certificate/key files.

The **Public PEM certificates** store imports, inspects, exports and removes
certificate references without requiring a private key. These records live in a
separate owner-only `certificates.json` beside the shared catalog, with a
`certificates` array; they are never advertised as TLS client identities or
installed as trust roots.

Select a row to inspect its fingerprint and certificate dates. Export public
writes only a normalized certificate to a new file. Existing destination files
are never overwritten. Export secret for a PEM identity requires confirmation
and writes a mode-0600 combined certificate and unencrypted PKCS#8 key backup;
keep that file secure.

## GnuPG and S/MIME

Choose OpenPGP or S/MIME, then Refresh to list public keys/certificates with full
fingerprints. The engines use `GNUPGHOME` when set, otherwise the usual GnuPG
home. Import accepts a selected public or secret key file; S/MIME also accepts a
PKCS#12 identity. OpenPGP Create asks for a user ID and delegates passphrase
creation to GnuPG's pinentry. S/MIME identities are imported rather than created.

Export public writes an armored public key/certificate to a new file. Export
secret requires a separate confirmation and writes a mode-0600 file. S/MIME
secret exports are PKCS#12. GnuPG's pinentry may ask for a passphrase only for an
explicit import, creation, secret export or secret deletion. Listing and public
exports use `--pinentry-mode error`. Public-key deletion is separate from the
explicit OpenPGP secret-and-public deletion choice. S/MIME public deletion is
provided; secret S/MIME deletion is left to the owning GnuPG tools. S/MIME command
arguments follow the [GnuPG certificate management interface](https://gnupg.org/documentation/manuals/gnupg/Certificate-Management.html).

Processes receive argument arrays without a shell. Their output is capped at
2 MiB and their execution at two minutes. GnuPG work runs outside the UI thread;
errors report the operation outcome without echoing key material. No keyserver
lookup, mail send, trust-root installation or background network operation is
implemented.

## Source

GPL-3.0-or-later. The FLTK appearance, BDF font, GPU window and universal-menu
adapters retain their MIT notices from the de-xr suite. The tray adapter derives
from Penguin Mail's GPL-3.0-or-later StatusNotifierItem implementation. This
project does not change the default toolkit or install/restart a desktop session.
