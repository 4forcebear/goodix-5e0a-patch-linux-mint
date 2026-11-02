# v1.0.3 — Mint encrypted-home login guard

Fixes fingerprint authentication delaying or hiding the password prompt at
the first LightDM login after a cold boot when the home uses eCryptfs.

## Behavior

On Linux Mint with `libpam-fingwit` installed, `./install.sh --pam` selects
the native Fingwit profile and disables the conflicting raw fprintd profile.
Fingwit skips fingerprint authentication at initial login when a password is
needed to decrypt the home. After login, the profile permits fingerprint
authentication for sudo and screen unlock.

The installer checks that Fingwit's one-rule skip directly precedes the
fingerprint rule, preserves the password fallback, and sets three fingerprint
attempts. It refuses unsafe raw setup for a detected encrypted home without
Fingwit. It does not force replacement of customized PAM stacks.

## Existing v1.0.2 installation

Update only the optional PAM setup as your normal user:

```bash
set -o pipefail
curl -fsSL https://raw.githubusercontent.com/4forcebear/goodix-5e0a-patch-linux-mint/v1.0.3/easy-install.sh | bash -s -- --pam
```

This saves a root-only backup of common PAM files and the profile manager's
state. Driver reinstallation and fingerprint re-enrollment are not required
for this PAM fix. Initial login to the encrypted home requires the password.

## Validation and scope

- Fourteen focused software tests passed: profile selection, execution of
  the actual PAM editing program against temporary fixtures, and existing
  installer CLI tests. Bash syntax and Git whitespace checks passed.
- The installed Mint policy was tested with a simulated absent desktop
  session and actual encrypted-home paths: it skips fingerprint for initial
  LightDM login and permits it for sudo/unlock.
- After applying the candidate and performing a cold boot on 2026-11-02,
  the user confirmed an immediate password prompt without fingerprint wait.
  LightDM logs show the password-backed session opening and login keyring
  unlocking. The Fingwit guard remained active after the boot.
- A later post-boot verification matched with score 41. Earlier genuine
  checks were intermittent (one match in three calls), so matching stability
  remains an open issue. This release does not claim to fix it.

The biometric driver and matching thresholds are unchanged from v1.0.2.
The full historical software suite is not claimed green. The curl bootstrap
is pinned to v1.0.3; older versioned URLs continue to fetch their old releases.
No fingerprint images or enrolled templates are included.
