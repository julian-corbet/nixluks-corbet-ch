# nixluks

**Declare which LUKS2 volumes a host unlocks post-boot, in what order, with
header-backup orchestration and drift verification wired to the same
declaration — one passphrase prompt for the whole set, and a passphrase this
module never once holds.**

## What nixluks is

Every host with more than one encrypted volume ends up hand-rolling the same
three things: a `crypttab` (or worse, a shell script) that opens them in the
right order so systemd's own kernel-keyring cache actually gets to reuse one
passphrase across all of them; a `cryptsetup luksHeaderBackup` nobody
remembers to run again after a key rotation; and no way to notice that a
keyslot got added by hand, or that a rotation only half-happened, until a
recovery is already underway. nixluks is the declared, generalised version of
the first of these three things — a mechanism that already existed,
field-proven, in the sibling
[nixnas](https://github.com/julian-corbet/nixnas) project's own
appliance-specific storage-unlock code — plus the two that never existed
anywhere before this repo.

**The mechanism, in one sentence**: each declared volume opens SERIALLY via
`systemd-cryptsetup@<name>.service` (systemd's own crypttab-generator units,
in a fixed order this module declares — `volumes.<name>.order` — never left
to Nix's own non-deterministic attribute order); the FIRST passphrase entered
is cached in the kernel keyring and opens every later volume silently — one
prompt for the whole set. This is systemd's own password cache, not anything
this module implements; the chain exists only to guarantee the order is
fixed and repeatable, which is what keeps the cache reliably warm.
Serialisation is load-bearing — parallel opens would each prompt
independently — so this module never parallelises the chain.

## The security model

**This module never touches key material. It cannot leak a passphrase
because it never has one.** The passphrase exists in exactly three places,
ever: the operator's head; the LUKS header on disk, as a KDF-wrapped master
key; and the kernel keyring, transiently, for the duration of the unlock
chain. It is NEVER the Nix store, NEVER a rendered config, NEVER committed to
git, NEVER a keyfile, and NEVER an environment variable.

What IS declared is deliberately all non-secret, public metadata about the
ciphertext: which devices are LUKS2 (by UUID or by-id — never a bare
`/dev/sdX`, kernel enumeration order is not stable), the mapper name each
opens as, the unlock ORDER, the unlock POLICY as a stance rather than a
credential (`raiseMode` — see "Hot mode" below), header-backup DESTINATIONS,
and the EXPECTED header shape (slot count, cipher, KDF) — public metadata
`cryptsetup luksDump` already reports without a passphrase, checked here only
so a live drift from the declaration is caught.

**The safety invariant**: nixluks only OPENS declared volumes and READS BACK
their headers. It never creates, `luksFormat`s, or destroys a device. This is
not just a comment to trust — `checks/default.nix`'s own
`structurally-safe` test reads the module's actual source text and fails the
build if a destructive/creating cryptsetup or filesystem call (`luksFormat`,
`luksAddKey`, `wipefs`, `mkfs.`, …) ever appears in its real code, comments
and option prose excluded.

**Enrollment is on the far side of that line too.** `systemd-cryptenroll` —
TPM2, FIDO2, recovery keys, any of it — WRITES a key slot, which is the same
class of act as `luksAddKey`: an enrollment that happens because a config file
changed is one nobody was standing at the machine to authorise, and reverting
the config does not undo it. `cryptenroll`, `luksChangeKey`, `luksConvertKey`
and `reencrypt` are in the same source-text check. See "TPM2: tooling, never
enrollment" below for the option that installs the userland and still enrolls
nothing.

**Header backups are sensitive.** A LUKS header backup is not the
passphrase, but it IS the KDF-wrapped master key plus every keyslot — with
the passphrase, it opens the volume exactly as completely as the original
would. `headerBackup.destination` refuses to build if it resolves under
`/tmp`, `/var/tmp`, or `/dev/shm`, and `nixluks-backup-headers` itself
refuses at runtime, before writing a single byte, if the destination
directory grants group/other access.

## Hot mode

The case a hub-class host needs and a rescue image does not:
`raiseMode = "preopened"` means every declared volume is ALREADY open by the
time stage-2 starts — either this repo's own `modules/initrd.nix` opened it
one stage earlier (`volumes.<name>.initrdUnlock.enable`; see "Boundaries"
below), or something else did (an operator's earlier manual `cryptsetup
open`). In that mode `nixluks-storage.target` auto-raises at boot but
depends on NOTHING — re-running an open against an already-open mapper is at
best a no-op and at worst a second prompt for a passphrase already consumed.
The default, `raiseMode = "cold"`, is the opposite: every volume is
genuinely locked when stage-2 starts, and `nixluks-unlock` raises the target
on demand.

## Boundaries — one knob, one owner

- **vs [nixboot](https://github.com/julian-corbet/nixboot-corbet-ch)**:
  nixboot's own `remoteUnlock` guards a DIFFERENT secret over a DIFFERENT
  channel — the TPM2-sealed initrd-SSH host key that lets an operator type a
  passphrase in remotely. It never declares, opens, or times out a LUKS
  member (nixboot has no member list to attach that to). Actually OPENING a
  declared volume in the initrd, one stage before switch-root, is
  `modules/initrd.nix` — a separate NixOS-only module this flake also
  exports (`volumes.<name>.initrdUnlock.{enable,critical,timeoutSec}`);
  system-manager has no `boot.initrd.*` surface at all, so it can never
  carry this (see "Two backends, one file" below). A volume that module
  already opened is declared here with `raiseMode = "preopened"`, never
  re-opened by the post-boot chain.
- **vs nixstorage**: nixstorage declares the medium's geometry — partitions,
  sizes, which region plays which role. nixluks declares the CRYPTO LAYER on
  a region nixstorage already named. Geometry → crypto → filesystem, three
  separate declarations, never one module doing all three.
- **vs [nixvault](https://github.com/julian-corbet/nixvault-corbet-ch)**:
  nixvault owns what goes INSIDE a vault, and how its contents are staged and
  committed. nixluks owns the KEYING — a vault is not a special case this
  module needs to know about, it is just another member of `volumes`, keyed
  and unlocked the same as any other declared disk. A mounted vault is also
  exactly the kind of place `headerBackup.destination` belongs: private,
  already encrypted, already part of the same recovery story.

## Two backends, one file

`nixosModules.default` and `systemManagerModules.default` are the same file
(`modules/nixluks.nix`), unchanged — nixluks only ever touches option surface
system-manager supports identically to NixOS (`environment.etc`,
`systemd.services`/`systemd.targets` including `overrideStrategy =
"asDropin"`, `assertions`/`warnings`, `environment.systemPackages`),
confirmed by reading system-manager's own module source rather than assumed.
This ONE file never needed `boot.*` or `users.*` — every `nixluks-*` tool
runs as whoever invokes it. Actually opening a volume in the initrd
(`volumes.<name>.initrdUnlock.*`, see "Boundaries" above) is a separate file,
`modules/initrd.nix` — a NixOS-only `nixosModule` never exported as a
`systemManagerModule`, because system-manager has no `boot.initrd.*` surface
at all. See `modules/nixluks.nix`'s own "ONE FILE, BOTH BACKENDS" header for
the full accounting, and `checks/default.nix`'s backend-parity tests for the
CI proof that both backends actually agree.

```nix
# On a foreign (non-NixOS) host applying its config via system-manager:
imports = [ inputs.nixluks.systemManagerModules.default ];
```

Two things genuinely differ on that backend, and nixluks handles both explicitly
rather than pretending the file is backend-blind:

**The host's own `cryptsetup`.** The crypttab nixluks writes is not read by
anything in the Nix store — it is read by the HOST's
`systemd-cryptsetup-generator`, and the units it generates run the host's own
`/usr/bin/systemd-cryptsetup`. On NixOS that arrives with the system's systemd
and nothing has to ask for it; on Arch it is an ordinary package that can be
absent, or present only as some other package's undeclared dependency — which is
not a declaration. So nixluks **publishes** the names it needs and the consumer
**connects** them to whatever installer that host uses:

```nix
nixarch.packages.pacman = config.nixluks.archPackages; # ⇒ [ "cryptsetup" ]
nixarch.packages.aur    = config.nixluks.aurPackages;  # ⇒ [ ] (nothing here lives in the AUR)
```

Nothing in this flake references any reconciler; both lists are plain strings,
and both are empty on a host where nixluks is off or declares no volume.

**`/etc/crypttab` is claimed only when nixluks actually owns an unlock** — i.e.
when at least one volume has `manageUnlock = true`. A host that declares its
volumes purely so their headers get backed up and their live shape verified
writes no crypttab at all. An empty one is a no-op on NixOS, but on a foreign
host `/etc/crypttab` is a real, pre-existing, distro-owned file that may already
carry that machine's root and swap unlock lines, and `environment.etc` replaces
a file wholesale rather than appending to it.

## TPM2: tooling, never enrollment

```nix
nixluks.tpm2.installTooling = true; # tpm2-tools on PATH. Enrolls NOTHING.
```

Deciding to TPM-seal a volume is a deliberate act performed by hand, at a
keyboard, against a specific device — and it needs `tpm2_getcap` /
`tpm2_pcrread` available *first*, to read what the machine's TPM and PCR state
actually are before anything is sealed to them. This option makes that tooling
available and does nothing else: no key slot is added, removed, changed or read,
and `systemd-cryptenroll` is never invoked.

That is not a promise this README makes — `cryptenroll`, `luksChangeKey`,
`luksConvertKey` and `reencrypt` sit in the same source-text check as
`luksFormat` and `luksAddKey` (see "The security model" above), and a further
test asserts that turning this option on changes the package set and *nothing*
else: byte-identical rendered unit commands, byte-identical crypttab.

## Usage

```nix
{
  inputs.nixluks.url = "github:julian-corbet/nixluks-corbet-ch";

  outputs = { self, nixpkgs, nixluks, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixluks.nixosModules.default

        {
          nixluks = {
            enable = true;
            raiseMode = "cold"; # or "preopened" -- see "Hot mode" above

            volumes = {
              archive0 = {
                device = "/dev/disk/by-id/ata-…"; # this exact disk, never /dev/sdX
                order = 1; # opens first; its passphrase primes the keyring cache
                role = "primary data pool";
                headerBackup.destination = "/mnt/vault/luksHeaderBackups/archive0.img";
                expect = {
                  cipher = "aes-xts-plain64";
                  slotCount = 1;
                  kdf = "argon2id";
                };
              };
              archive1 = {
                device = "/dev/disk/by-uuid/…"; # or the LUKS container's own UUID
                order = 2; # opens silently, from the cached passphrase above
              };
            };
          };
        }
      ];
    };
  };
}
```

Then, on that host:

```console
$ sudo nixluks-unlock            # one passphrase, every declared volume opens
$ sudo nixluks-backup-headers    # copies each declared header to its destination
$ sudo nixluks-verify            # compares live headers against the declaration
```

Downstream mounts are native NixOS/system-manager, not this module's job —
gate a `fileSystems` entry on the same target nixnas's own precedent already
documents:

```nix
fileSystems."/data" = {
  device = "/dev/mapper/archive0";
  options = [ "noauto" "x-systemd.wanted-by=nixluks-storage.target" ];
};
```

## Status

The module and its three tools are complete, exported for both NixOS and
system-manager, and covered by eval-time tests (including backend parity, a
mechanical check that the module's own code contains no destructive/creating
cryptsetup or enrolling call, and a check that `/etc/crypttab` is claimed only
when nixluks actually owns an unlock) plus a real `pkgs.testers.nixosTest`
runtime harness (`checks/lifecycle-vm-test.nix`) that opens two real LUKS2
volumes from one passphrase prompt, proves the second opens from the kernel
keyring cache with no second prompt, proves a wrong passphrase fails cleanly,
proves `nixluks-verify` catches a hand-added keyslot with a different KDF,
and proves a header backup is a real, independently readable LUKS2 header.

## Repository layout

| Path | Purpose |
|---|---|
| `flake.nix` | Flake entry point: `nixosModules.default` / `systemManagerModules.default` (the same file, both backends), the separately-exported `nixosModules.initrd`, and `lib.devicePathType`. |
| `modules/nixluks.nix` | The module: options, assertions, the serial unlock chain, and the three tools. |
| `modules/initrd.nix` | NixOS-only `nixosModule` (never a `systemManagerModule`): opens `volumes.<name>.initrdUnlock`-enabled volumes IN THE INITRD, one stage before switch-root. |
| `lib/device-path.nix` | The by-id/by-uuid device type, exposed so a consumer can validate a device string without a full eval. |
| `checks/` | Eval-time tests (including backend parity and the structurally-safe check) plus the real `pkgs.testers.nixosTest` lifecycle harness, all wired into `nix flake check`. |
| `docs/index.md` | The design walkthrough: the serial chain in detail, the ask-password protocol the VM test drives, and why `order` is explicit rather than name-derived. |
| `experiments/` | Runnable trials with recorded results — see [`experiments/README.md`](experiments/README.md). |
| `studies/` | Written investigations that motivate design decisions — see [`studies/README.md`](studies/README.md). |

## Related projects

Part of the same small, independently-usable NixOS module family:
[nixnas](https://github.com/julian-corbet/nixnas) (the field-proven
serial-unlock-with-keyring-cache mechanism this module generalises out of its
`modules/storage/connect.nix`), [nixvault](https://github.com/julian-corbet/nixvault-corbet-ch)
(the VM-test pattern this project's own `checks/lifecycle-vm-test.nix`
copies, and the module this repo's own vault-as-a-chain-member boundary
refers to), [nixfs](https://github.com/julian-corbet/nixfs-corbet-ch) (the
"one file, both backends" export shape this project's dual-backend export
copies), and [nixboot](https://github.com/julian-corbet/nixboot-corbet-ch)
(the prose-option, one-knob-one-owner house style, and the initrd-side unlock
`raiseMode = "preopened"` composes with). nixluks has no build-time dependency
on any of them — it is built to sit on any host, independent of whatever
boot stance or vault that host uses.

## License

[MIT License](LICENSE) &copy; 2026 Julian Corbet
