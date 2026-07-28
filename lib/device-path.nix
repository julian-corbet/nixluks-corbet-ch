# lib/device-path.nix
#
# The one type nixluks needs from its host's disk layer, factored out so a consumer can validate
# a device string against the SAME rule this module enforces without pulling in the whole flake
# eval -- same reason nixfs exposes lib.catalogue and nixvault exposes lib.manifest.
#
# WHY by-id / by-uuid ONLY, never a bare /dev/sdX or /dev/nvme0n1pN: kernel device-enumeration
# order is assigned at probe time and is not guaranteed stable across a reboot, a controller
# change, or a disk pulled and reinserted in a different port -- exactly the nixnas precedent
# (modules/storage/connect.nix's own `diskById` type) this generalises. Two stable identities are
# accepted, not one, because they answer different questions:
#   by-id:   "this exact physical/logical disk instance" -- stable as long as the same drive
#            stays attached, follows the controller/port, not the data on it.
#   by-uuid: "this exact LUKS container" -- stable as long as the header survives, follows the
#            CIPHERTEXT (recorded inside the LUKS metadata itself), not the physical disk it
#            currently sits on. This is the one a rescue operator wants when a disk was cloned,
#            replaced, or moved: "open the volume with this UUID", regardless of which /dev/sdX
#            or by-id path it turned up under on THIS boot.
{ lib }:

lib.types.strMatching "/dev/disk/by-(id|uuid)/.+"
