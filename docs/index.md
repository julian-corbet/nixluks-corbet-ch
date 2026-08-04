# nixluks — design walkthrough

## The mechanism, restated in full

This module is an extraction, not an invention. The serial-unlock-with-
keyring-cache mechanism is lifted directly from the sibling
[nixnas](https://github.com/julian-corbet/nixnas) project's
`modules/storage/connect.nix` (`storage.unlock`), which has run in
production against real disks. What follows restates that design in
host-agnostic terms.

Each declared volume in `nixluks.volumes` opens via
`systemd-cryptsetup@<name>.service` — a unit systemd's own crypttab
generator creates from the `/etc/crypttab` line this module renders, not
anything nixluks writes itself. Left alone, each of those units would
independently ask for its own passphrase. What this module adds is exactly
one thing: an `after=` dependency chaining each unit to the one before it,
in a fixed order (`volumes.<name>.order`, lowest first, ties broken by
name — never Nix's own attribute-definition order, which the language does
not preserve). That fixed order is the whole mechanism. Once it is fixed,
systemd's own password cache — a per-boot kernel keyring, not anything this
module implements — does the rest: the first successful passphrase is
cached, and every later `systemd-cryptsetup@` invocation tries cached
passphrases before ever generating a fresh prompt. Serialisation is load-
bearing precisely because of this: two units starting in parallel would each
generate an independent prompt before either could benefit from the other's
answer, so this module never parallelises the chain, no matter how tempting
that looks for a host with many volumes.

## Why `order` is an explicit field, not the attribute name

connect.nix's own implementation relies on `attrNames`, which Nix guarantees
returns lexicographically sorted names — a fine solution for an appliance
where the operator names disks `archive0`, `archive1`, … in the order they
should open. It is a worse fit for a host, a rescue image, or a
vault, where a volume's most natural name (a role: `vault`, `primary`,
`backup-target`) often has no relationship to the order it should unlock in.
nixluks makes `order` its own field for exactly this reason: naming and
sequencing are different concerns, and forcing one to encode the other is
the kind of coupling this whole family of modules tries not to introduce
(see nixstorage's own `nixiam`/`nixstorage` split for the same argument made
about identity and storage shape). The determinism connect.nix's own header
calls load-bearing is preserved exactly — `order` with the volume name as a
tie-break is still a total, repeatable ordering, just sourced from a field
instead of forced through a naming convention.

## The ask-password protocol, and why the VM test needs it

`systemd-cryptsetup@<name>.service` has no controlling terminal of its own —
it is a plain background service, not an interactive shell. When it needs a
passphrase, it does not read a console directly; it writes a descriptor file
under `/run/systemd/ask-password/` naming a `Socket=` path, and waits for a
`SOCK_DGRAM` datagram of the form `b"+" + password` sent to that path. A
human answers this via `systemd-tty-ask-password-agent`, which reads a real
terminal and forwards the answer over exactly this protocol — the same
protocol `nixluks-unlock`'s own polling loop invokes that agent to service.
`checks/lifecycle-vm-test.nix` answers the same way, scripted: it is not a
mock of the mechanism, it is the same wire protocol systemd's own agent
speaks, verified directly against `src/shared/ask-password-api.c` in
systemd's own source rather than assumed. This is also *why* the test can
prove the keyring cache claim concretely rather than merely asserting it:
the test sends exactly one answer, then waits for the SECOND volume's mapper
to appear with no second answer ever sent and no second `ask.*` file left
pending — which only happens if the kernel genuinely served the cached
passphrase.

## Hot mode, and why it is a single two-value stance

`raiseMode` answers one question — has every declared volume already been
opened by the time stage-2 starts? — never a richer per-volume policy,
because the underlying reality it describes is whole-host, not per-volume:
an initrd unlock (this repo's own `modules/initrd.nix`,
`volumes.<name>.initrdUnlock.*` — a distinct mechanism from nixboot's
`remoteUnlock`, which guards the initrd-SSH host key, not a LUKS member)
either ran against the whole set the initrd knew about, or it didn't; there
is no scenario where half a host's declared volumes arrive pre-opened and
half do not, without that already being two different hosts' worth of
configuration. Keeping it a single enum, rather than a per-volume field,
keeps the one invariant this module structurally guarantees intact: exactly
one code path can ever start a given `systemd-cryptsetup@<name>.service` —
either the `cold`-mode target's own `wants=`, or nothing at all (`preopened`
mode never lists it) — never both, and never a third path this module would
need to reason about per volume.

## Header backups: why the runtime check exists alongside the eval-time one

`headerBackup.destination` is checked twice, for different failure modes.
The eval-time assertion (`/tmp`, `/var/tmp`, `/dev/shm` refused outright)
catches an obviously wrong destination before a single byte is built into
any configuration — cheap, and catches the mistake as early as possible.
The runtime check inside `nixluks-backup-headers` (refusing a destination
directory that grants group/other access, checked immediately before
writing) catches the failure mode the eval-time check structurally cannot:
a destination that was PRIVATE when the configuration was written, but whose
actual directory permissions drifted afterward — a vault re-mounted with the
wrong options, a `chmod` typo, a filesystem that reset permissions on
remount. `checks/lifecycle-vm-test.nix` proves both halves of this
independently: the eval-time refusal in `checks/default.nix`, and the
runtime refusal (plus the more important half — that ONE misconfigured
destination never blocks another, correctly-configured volume's backup)
in the VM test.

## `nixluks-verify` and the failure it exists to catch

The motivating case is concrete, not hypothetical: a key on a real host had
rotated twice and lost twice, and nothing noticed either time — because
nothing was reading the header back and comparing it to what was supposed to
be there. `cryptsetup luksDump --dump-json-metadata` reports a LUKS2
header's shape without needing a passphrase at all (it is public metadata:
which cipher, how many occupied keyslots, which KDF each one uses — never
the wrapped key's actual bytes in a form that reveals anything about the
passphrase). `nixluks-verify` compares that live shape against
`volumes.<name>.expect.*` and fails loudly on any mismatch, catching both
drift directions on slot count — a keyslot added by hand (drift up) and a
rotation that removed the old slot without the new one ever landing (drift
down) — and a keyslot added with a weaker or different KDF than the ones
the declaration expects. `checks/lifecycle-vm-test.nix` proves this for
real: it hand-adds a second keyslot with a different KDF, outside the
module's own knowledge entirely, and confirms `nixluks-verify` reports
exactly that drift.

## What is deliberately not here

No ZFS pool import, no filesystem mount, no dependent-service wiring beyond
naming the target they should gate on. `connect.nix`'s own appliance
convenience (`storage.zfsPools`, importing pools as part of the same unlock)
is nixnas-specific and stays there — folding it into nixluks would mean this
module's scope grew to include "what do you do once it's open," which is
exactly the boundary the README's "vs nixstorage" section exists to hold.
A consumer wanting that convenience composes it themselves, the same way any
`fileSystems` entry or `systemd.services` unit gates on
`nixluks-storage.target` today.

No enrollment either — not TPM2, not FIDO2, not a recovery key. Every one of
those writes a key slot, and a key slot that appears because a config file
changed is one nobody was at the machine to authorise; reverting the config
does not take it back. `tpm2.installTooling` is the deliberate half-step: it
puts `tpm2-tools` on PATH so an operator can READ what the machine's TPM and
PCR state actually are, and the act of sealing anything to them stays a
human-at-a-keyboard decision made with `systemd-cryptenroll` directly.

No ownership of a foreign `/etc/crypttab`. On a non-NixOS host that file
predates nixluks and can carry the machine's root and swap unlock lines;
`environment.etc` replaces a file wholesale rather than appending, so nixluks
writes it only when at least one volume has `manageUnlock = true` — i.e. only
when it has a line of its own to put there. A host declaring volumes purely
for header backup leaves the file alone entirely.
