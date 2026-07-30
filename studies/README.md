# Studies

Written investigations that motivate design decisions -- comparisons, failed
approaches, upstream research. Cross-linked from
[`experiments/`](../experiments/README.md) where a study led to a runnable
experiment.

No studies have been written yet. The material that would seed the first one
already exists as evidence inside the module itself rather than as a separate
document -- see `modules/nixluks.nix`'s own SCOPE block for why nixboot's
`remoteUnlock` (a different secret, the initrd-SSH host key, not a LUKS
member), the medium's geometry (nixstorage), and a vault's contents
(nixvault) were each ruled out as part of THIS FILE's domain -- and, by
contrast, why actually opening a declared volume in the initrd
(`volumes.<name>.initrdUnlock.*`) is instead a separate NixOS-only file in
this same repo, `modules/initrd.nix` -- plus the module's "HOT MODE" section
for why `raiseMode` is a two-value stance rather than a richer per-volume
policy. A written study belongs here once that reasoning
needs to be argued from prior art (other distros' crypttab tooling, other
LUKS-orchestration projects) rather than restated from the module's own
comments -- or once `checks/lifecycle-vm-test.nix`'s own "NOT tested here"
note (the system-manager backend has no real runtime-boot proof, only eval
parity) needs a real trial on a non-NixOS host to close.
