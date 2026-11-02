# 121 — Restore Mint encrypted-home login guard
Status: closed

Verdict: confirmed for the initial encrypted-home login gate after a deployed
PAM change and a user-performed cold boot on 2026-11-02. Matching reliability
is not included in this verdict.

## Problem and cause

After a reboot, LightDM offers fingerprint authentication before the password.
Touching the sensor fails to produce a usable login; leaving it alone reaches
the verification timeout and eventually offers the password. The installed
`common-auth` used raw `pam_fprintd.so` followed by `pam_unix.so` and
`pam_ecryptfs.so unwrap`, with the Mint Fingwit guard disabled by the earlier
clean PAM reset. The current home mount is eCryptfs.

The installed Mint `libpam-fingwit` policy explicitly returns
`PAM_AUTHINFO_UNAVAIL` for an initial login with an encrypted home and no
existing desktop session. The profile's one-rule jump skips fprintd and goes
directly to Unix password authentication. With an existing session, it permits
fingerprint attempts for sudo and screen unlock.

## Change and deployed state

- Prefer the installed Fingwit profile, disable the conflicting raw fprintd
  profile through `pam-auth-update`, and preserve the three-attempt setting.
- Verify the guard immediately precedes fprintd, with its exact one-rule
  skip. Refuse editing if it is absent or the password fallback is missing.
- Refuse raw automatic PAM setup for a detected encrypted home without
  Fingwit. Do not force replacement of a locally customized PAM stack.
- Save the profile manager's state in addition to the existing PAM backup.
- Applied `./install.sh --pam` from this candidate on 2026-11-02 at 20:28 MSK.
  Selected Fingwit; active order: Fingwit guard, fprintd with three attempts
  and timeout 15, Unix password, existing eCryptfs unwrap.
- Driver library, matching thresholds and enrolled print were not changed.

## Evidence and limits

Fourteen focused tests passed: profile selection, execution of the actual
PAM editing program on temporary files, and existing installer CLI tests.
Missing/misplaced guard and missing password cases fail without writing.

The installed Fingwit Python policy was executed with a simulated absent
desktop session and real encrypted-home paths. Initial LightDM login returned
PAM_AUTHINFO_UNAVAIL; sudo and Cinnamon unlock returned PAM_IGNORE. This is
policy verification, not an actual post-reboot login.

The unchanged driver passed installation checks. Three genuine direct calls
after this boot returned no-match, match, no-match. First failed burst had
frame quality 71–80 and Milan raw scores -5/-4. This remains evidence of
variable matching, not universal scanner reliability. Do not lower thresholds
or delete the stored print to conceal the issue.

## Cold-boot result

The user confirmed that cold startup now requests only the password, without
a fingerprint prompt. The new boot's LightDM journal shows authentication
starting at 20:34:43 MSK and the password-backed session opening at 20:34:52,
with the login keyring unlocked. The installed common-auth still has the
Fingwit guard directly before fprintd and retains the Unix password fallback.
A later verification at 20:40:35 returned a genuine match with score 41.

The initial-login gate is confirmed on this unit. This does not establish
universal matching reliability or behavior of a home without encryption.

## Verification protocol and follow-up

After the user saves open work, reboot normally and inspect the first LightDM
login. The sensor hands-off/hold protocol is not relevant to this PAM-only
gate: the predicted behavior is that the sensor is skipped before decryption.

- Confirm: password prompt appears directly, without a fingerprint prompt or
  verification timeout. LightDM session opens and encrypted home mounts after
  the password. After login, confirm the Fingwit guard remains enabled.
- Falsify: initial login still starts fingerprint verification, hides the
  password, or fails password authentication.
- Inconclusive: reboot/login is not exercised, or logs do not distinguish an
  initial login from unlock of an existing session.

Matching variability remains a separate open issue to diagnose with preserved
templates and unchanged match decisions. The single next matching experiment
is repeated verification after a cold boot with recorded per-attempt scores;
do not relabel the initial-login result as a matching fix.
