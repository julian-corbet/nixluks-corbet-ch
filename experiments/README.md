# Experiments

Runnable experiments with recorded results. Each experiment gets its own
directory with a README stating hypothesis, method, and outcome.
Cross-linked from [`studies/`](../studies/README.md) where a study motivated
it.

No experiments have been run yet. Candidates:

- A real-hardware trial of `nixluks-backup-headers` writing to an actual
  offline/removable destination (a USB stick, a second machine over the
  network) rather than the local-filesystem destinations `checks/lifecycle-vm-test.nix`
  covers, to confirm the private-directory refusal behaves identically once
  a real removable medium's default permissions are involved.
- A timing measurement of the serial unlock chain's real-world cost as the
  number of declared volumes grows (each `systemd-cryptsetup@` unit adds one
  `After=` hop) -- the mechanism is documented as fine for a handful of
  volumes; nothing here has measured where "a handful" stops being true.
- A trial of `raiseMode = "preopened"` against a real initrd that opened
  volumes via this repo's own `modules/initrd.nix`
  (`volumes.<name>.initrdUnlock.enable`), to confirm the initrd's own opened
  mappers really do satisfy `nixluks-storage.target` with zero re-open
  attempts on a real boot, not just in `checks/default.nix`'s eval-level
  rendering of that mode.
