# checks/lifecycle-vm-test.nix
#
# THE ONE REAL RUNTIME TEST in this project. Everything else under checks/ is eval-only. This is
# a `pkgs.testers.nixosTest` (ephemeral QEMU, nothing persists after the build) that exercises the
# WHOLE unlock chain against REAL LUKS2 volumes, on REAL loop devices, exactly the way an operator
# would -- adoption of the house pattern nixvault's own checks/lifecycle-vm-test.nix and nixram's
# swappiness-relief-vm-test.nix already proved out (see either file's own header for the model this
# one copies), not invention.
#
# HARD SAFETY: every "disk" this test touches is a plain, pre-sized regular FILE created inside
# THIS VM's own ephemeral root, attached to a loop device THIS VM's own kernel allocates
# (`losetup`) -- never a real or emulated block device, never `/dev/sdX`, never anything that
# outlives the build. Nothing here is reachable from, or shares any device node with, the host
# this test happens to build on.
#
# THE ONE DESIGN CHOICE WORTH EXPLAINING: how the FIRST passphrase answer is delivered without a
# real terminal. `systemd-cryptsetup@<name>.service` has no controlling tty of its own (it is a
# plain oneshot service, not an interactive session), so a pending passphrase query always goes
# through systemd's own ask-password protocol: an `ask.*` descriptor file under
# `/run/systemd/ask-password/` naming a `Socket=` path, answered by sending a `SOCK_DGRAM`
# datagram of the form `b"+" + password` to that path (verified directly against systemd's own
# `src/shared/ask-password-api.c`, the exact wire format `systemd-tty-ask-password-agent` itself
# speaks when a human answers interactively). `answerAskPassword` below does exactly that, nothing
# more -- it is the scripted equivalent of an operator typing into the agent nixluks-unlock's own
# polling loop invokes, not a mock of the mechanism, since it drives the REAL protocol.
#
# WHAT THIS PROVES, in the order it happens below:
#
#   1. `nixluks-backup-headers` refuses a destination whose parent directory grants group/other
#      access, WITHOUT touching that volume's header -- and keeps working for every OTHER declared
#      volume whose destination is private, proving partial-failure never becomes total failure.
#   2. THE WHOLE POINT: raising `nixluks-storage.target` opens TWO declared LUKS2 volumes with ONE
#      passphrase prompt -- the first volume's `systemd-cryptsetup@` unit raises a real
#      ask-password query, answered once; the SECOND volume's mapper appears with NO second query
#      ever created, because the kernel keyring cache -- systemd's own, not anything this module
#      implements -- served it silently. This is proven, not asserted: the test waits for the
#      second mapper with no second answer ever sent, and confirms no ask-password file is left
#      pending afterward. `nixluks-unlock` itself (the same `systemctl start` under a
#      password-surfacing polling loop) is exercised right after, in the one scenario that cannot
#      race that loop's own background `systemd-tty-ask-password-agent` call: everything already
#      open, nothing left to prompt for.
#   3. THE FAILING DIRECTION: a WRONG passphrase against one of the same volumes, via a bare
#      `cryptsetup open`, fails cleanly and leaves no mapper behind.
#   4. `nixluks-verify` reports a clean match against the freshly-formatted headers' real shape
#      (cipher, slot count, kdf) -- then, after a keyslot is added BY HAND with a different KDF
#      (outside this module's own knowledge, exactly the "half-happened rotation" scenario this
#      tool exists to catch), reports the drift and fails loudly.
#   5. `nixluks-backup-headers`, once its earlier refusal is corrected (the destination directory
#      re-permissioned to private), writes a header backup for every declared volume that a bare
#      `cryptsetup luksDump` can read back directly as a valid LUKS2 header -- proving the backup
#      is a real, usable header copy, not just a file that happens to exist.
#
# NOT tested here: the system-manager backend (nixosTest is NixOS-only by construction; the
# backend-parity eval checks in checks/default.nix are what proves the two backends render the
# same option surface, which is the only thing that differs between them).

{ pkgs, nixluksModule }:

let
  testPassphrase = "nixluks-test-passphrase-throwaway";
  wrongPassphrase = "definitely-the-wrong-passphrase";

  # Fixed, chosen-by-us LUKS UUIDs (not device-managed `/dev/disk/by-id/…`) for the two test
  # volumes. A loop device backing a plain file has NO real by-id identity for udev to populate
  # (by-id comes from actual hardware attributes -- ata/scsi/wwn -- a loopback file has none), so
  # a hand-made by-id symlink would be invisible to systemd's OWN device-unit tracking (which is
  # driven entirely by real udev events, never by a symlink merely existing on disk) and
  # `systemd-cryptsetup@<name>.service` would wait forever on a device unit that can never
  # activate. `--uuid=` at format time gives cryptsetup a REAL LUKS UUID udev's own blkid probe
  # recognises, so `/dev/disk/by-uuid/<uuid>` is populated the same way it would be for a real
  # disk -- proven below, not assumed.
  alphaUuid = "a10a1000-0000-4000-8000-000000000001";
  betaUuid = "b20b1000-0000-4000-8000-000000000002";

  answerAskPassword = pkgs.writeShellApplication {
    name = "answer-ask-password";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      python3 - "$1" <<'PYEOF'
      import glob
      import socket
      import sys

      pw = sys.argv[1].encode()
      answered = 0
      for f in glob.glob("/run/systemd/ask-password/ask.*"):
          sock_path = None
          for line in open(f):
              if line.startswith("Socket="):
                  sock_path = line.strip().split("=", 1)[1]
                  break
          if sock_path:
              s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
              s.sendto(b"+" + pw, sock_path)
              answered += 1
      print(f"answer-ask-password: answered {answered} pending quer{'y' if answered == 1 else 'ies'}")
      PYEOF
    '';
  };
in
pkgs.testers.nixosTest {
  name = "nixluks-lifecycle";

  nodes.machine = { pkgs, lib, ... }: {
    imports = [ nixluksModule ];

    nixluks = {
      enable = true;
      raiseMode = "cold";
      volumes = {
        alpha = {
          device = "/dev/disk/by-uuid/${alphaUuid}";
          order = 1;
          role = "primary test volume";
          headerBackup.destination = "/root/vault-headers/alpha/hdr.img";
          expect = {
            cipher = "aes-xts-plain64";
            slotCount = 1;
            kdf = "argon2id";
          };
        };
        beta = {
          device = "/dev/disk/by-uuid/${betaUuid}";
          order = 2;
          role = "secondary test volume -- must open from the keyring cache, no second prompt";
          headerBackup.destination = "/root/vault-headers/beta/hdr.img";
          expect = {
            cipher = "aes-xts-plain64";
            slotCount = 1;
            kdf = "argon2id";
          };
        };
      };
    };

    environment.systemPackages = [
      pkgs.cryptsetup
      pkgs.python3
      pkgs.util-linux
      answerAskPassword
    ];

    boot.kernelModules = [ "dm-crypt" "dm_mod" "loop" ];

    virtualisation.memorySize = 1024;
    virtualisation.cores = 2;
  };

  testScript = ''
    import time

    # Nix-interpolated ONCE, here, into real Python variables -- every later f-string below
    # references these two names, not the Nix `let` bindings of the same name (which have no
    # visibility into this string's own Python runtime at all).
    testPassphrase = "${testPassphrase}"
    wrongPassphrase = "${wrongPassphrase}"
    alphaUuid = "${alphaUuid}"
    betaUuid = "${betaUuid}"
    alphaDevice = "/dev/disk/by-uuid/" + alphaUuid
    betaDevice = "/dev/disk/by-uuid/" + betaUuid


    def wait_for_ask_password(timeout=30):
        for _ in range(timeout):
            out = machine.succeed(
                "ls /run/systemd/ask-password/ 2>/dev/null | grep -c '^ask\\.' || true"
            ).strip()
            if out not in ("", "0"):
                return True
            time.sleep(1)
        return False


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("pre-size two throwaway volumes as plain regular FILES, attach as loop devices"):
        machine.succeed("truncate -s 64M /root/vol-alpha.img")
        machine.succeed("truncate -s 64M /root/vol-beta.img")
        loop_alpha = machine.succeed("losetup -f --show /root/vol-alpha.img").strip()
        loop_beta = machine.succeed("losetup -f --show /root/vol-beta.img").strip()

    with subtest("format both volumes LUKS2 with a FIXED uuid, the SAME passphrase for both -- the whole premise of the keyring-cache test"):
        # `--uuid=` gives cryptsetup a real LUKS UUID; udev's own blkid probe recognises the
        # crypto_LUKS signature once written and populates /dev/disk/by-uuid/<uuid> for real --
        # unlike a hand-made by-id symlink, this is a genuine udev-tracked device systemd's own
        # device-unit machinery can actually wait on and activate against.
        machine.succeed(
            f"echo '{testPassphrase}' | cryptsetup luksFormat --type luks2 --uuid {alphaUuid} --batch-mode {loop_alpha}"
        )
        machine.succeed(
            f"echo '{testPassphrase}' | cryptsetup luksFormat --type luks2 --uuid {betaUuid} --batch-mode {loop_beta}"
        )
        machine.succeed("udevadm settle")
        machine.wait_for_file(alphaDevice, timeout=30)
        machine.wait_for_file(betaDevice, timeout=30)
        machine.succeed(f"cryptsetup isLuks {alphaDevice}")
        machine.succeed(f"cryptsetup isLuks {betaDevice}")

    with subtest("nixluks-backup-headers REFUSES a destination directory that grants group/other access, but still backs up the OTHER (private) volume"):
        machine.succeed("mkdir -p /root/vault-headers/alpha /root/vault-headers/beta")
        machine.succeed("chmod 0755 /root/vault-headers/alpha")  # deliberately wrong
        machine.succeed("chmod 0700 /root/vault-headers/beta")  # correct
        out = machine.fail("nixluks-backup-headers")
        assert "FAIL" in out, out
        assert "grants group or other access" in out, out
        machine.fail("test -e /root/vault-headers/alpha/hdr.img")
        machine.succeed("test -e /root/vault-headers/beta/hdr.img")
        machine.succeed("stat -c '%a' /root/vault-headers/beta/hdr.img | grep -qx 600")

    with subtest("correcting the directory's permissions lets nixluks-backup-headers succeed for BOTH volumes"):
        machine.succeed("chmod 0700 /root/vault-headers/alpha")
        machine.succeed("rm -f /root/vault-headers/beta/hdr.img")
        out = machine.succeed("nixluks-backup-headers")
        assert "PASS  alpha" in out, out
        assert "PASS  beta" in out, out
        machine.succeed("stat -c '%a' /root/vault-headers/alpha/hdr.img | grep -qx 600")

    with subtest("a header backup is a REAL, independently readable LUKS2 header -- not just a file that exists"):
        machine.succeed("cryptsetup luksDump /root/vault-headers/alpha/hdr.img")
        machine.succeed("cryptsetup luksDump /root/vault-headers/beta/hdr.img")
        alpha_uuid = machine.succeed(f"cryptsetup luksUUID {alphaDevice}").strip()
        backup_uuid = machine.succeed(
            "cryptsetup luksUUID /root/vault-headers/alpha/hdr.img"
        ).strip()
        assert alpha_uuid == backup_uuid, f"backup header UUID {backup_uuid} != live device UUID {alpha_uuid}"
        assert alpha_uuid == alphaUuid, f"live device UUID {alpha_uuid} != the fixed UUID this test formatted it with"

    with subtest("nixluks-verify PASSes against the freshly-formatted, undrifted headers"):
        out = machine.succeed("nixluks-verify")
        assert "PASS  alpha: cipher" in out, out
        assert "PASS  alpha: slot count" in out, out
        assert "PASS  alpha: every occupied keyslot uses kdf" in out, out
        assert "PASS  beta: cipher" in out, out
        assert "nixluks-verify: every declared volume" in out, out

    with subtest("THE WHOLE POINT: raising nixluks-storage.target opens BOTH volumes from ONE passphrase prompt"):
        # This is the exact mechanism `nixluks-unlock` itself invokes as its own first line
        # (`systemctl start --no-block nixluks-storage.target`) -- driven directly here, rather
        # than through that wrapper, so the ONE answer sent below races against nothing except
        # the real systemd chain: `nixluks-unlock`'s own polling loop additionally runs
        # `systemd-tty-ask-password-agent --query` in the background, which (with no real
        # terminal attached) would otherwise race this test's own scripted answer for the SAME
        # pending query. The declared chain under test -- the crypttab-generated units, the
        # `after=` ordering, the kernel keyring cache -- is identical either way; see the next
        # subtest for `nixluks-unlock` itself, exercised in the one scenario that cannot race it.
        machine.succeed("systemctl start --no-block nixluks-storage.target")
        assert wait_for_ask_password(), "expected an ask-password query for the FIRST volume (alpha) to appear"
        # Answered ONCE. If beta's mapper below appears without this ever running a second time,
        # the kernel keyring cache -- not this module -- served it silently.
        answer_out = machine.succeed(f"answer-ask-password '{testPassphrase}'")
        assert "answered 1" in answer_out, answer_out
        machine.wait_for_file("/dev/mapper/alpha", timeout=30)
        machine.wait_for_file("/dev/mapper/beta", timeout=30)
        # No pending query left behind for beta -- the ONLY answer sent above was for alpha.
        pending = machine.succeed("ls /run/systemd/ask-password/ 2>/dev/null | grep -c '^ask\\.' || true").strip()
        assert pending in ("", "0"), f"a second ask-password query is still pending: {pending}"
        machine.succeed("systemctl is-active systemd-cryptsetup@alpha.service")
        machine.succeed("systemctl is-active systemd-cryptsetup@beta.service")
        machine.succeed("systemctl is-active nixluks-storage.target")

    with subtest("nixluks-unlock itself: idempotent when everything it declares is already open, never blocks"):
        # Both volumes are already open from the subtest above, so `nixluks-storage.target` is
        # already active and NOTHING is queued when this starts it again -- `nixluks-unlock`'s own
        # polling loop condition is false before its body ever runs once, so this exercises the
        # real tool's own status-reporting path with no ask-password race possible.
        out = machine.succeed("nixluks-unlock")
        assert "nixluks-storage.target: active" in out, out

    with subtest("THE FAILING DIRECTION: a WRONG passphrase fails cleanly, leaves no mapper behind"):
        machine.succeed("cryptsetup close alpha")
        machine.succeed("cryptsetup close beta")
        machine.fail(
            f"echo '{wrongPassphrase}' | cryptsetup open --test-passphrase {alphaDevice}"
        )
        machine.fail(
            f"echo '{wrongPassphrase}' | cryptsetup open {alphaDevice} wrong-attempt"
        )
        machine.fail("test -e /dev/mapper/wrong-attempt")
        # Reopen cleanly with the RIGHT passphrase for the rest of the test.
        machine.succeed(f"echo '{testPassphrase}' | cryptsetup open {alphaDevice} alpha")
        machine.succeed(f"echo '{testPassphrase}' | cryptsetup open {betaDevice} beta")

    with subtest("nixluks-verify DETECTS drift: a keyslot added BY HAND, with a different KDF, outside this module's knowledge"):
        machine.succeed(
            f"printf '{testPassphrase}\\nnewkeyslot\\nnewkeyslot\\n' | cryptsetup luksAddKey --pbkdf pbkdf2 {alphaDevice}"
        )
        out = machine.fail("nixluks-verify")
        assert "FAIL  alpha: expected 1 occupied keyslot" in out, out
        assert "FAIL  alpha: expected every keyslot to use kdf" in out, out
        assert "PASS  beta" in out, out  # beta was never touched -- still clean

    with subtest("INCIDENTAL: what the kernel keyring looked like right after the unlock above"):
        # Not a pass/fail gate -- the actual proof that the cache served the second volume is the
        # subtest above (one answer sent, both mappers appeared, no second query ever pending).
        # `systemd-cryptsetup` caches under the description "cryptsetup" in the kernel USER
        # keyring per systemd's own src/shared/ask-password-api.c (`add_key("user",
        # "cryptsetup", …)`), keyed to the SERVICE's own keyring scope -- which is why a `keyctl`
        # read from this test's separate root shell is not a reliable place to assert on it, only
        # to log it for a human reading this test's output.
        print(machine.succeed("keyctl show @u 2>&1 || true"))
  '';
}
