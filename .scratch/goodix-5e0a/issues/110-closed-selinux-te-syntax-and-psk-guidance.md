# 110 — Fix SELinux policy syntax and improve per-device PSK guidance (Issues #10, #11)

**What was built:**
1. Fixed comment syntax in packaging/selinux/goodix-engine.te. SELinux Type Enforcement files require # comments instead of ; comments, which previously broke checkmodule on Fedora 44 with "ERROR 'Building a policy module, but no module specification found.' at token ';' on line 1".
2. Added checkpolicy to Fedora/RHEL dependencies in install.sh.
3. Enhanced install.sh checks and integration to detect active SELinux policy and warn if /etc/libfprint/goodix-5e0a.psk is missing.
4. Added diagnostic log in goodixtls.c when SSL_accept fails with bad record MAC (0x0A000119) or cipher failure (0x1C800066), guiding users to docs/psk-extraction.md.
5. Added validation in goodix5e0a.c for malformed PSK override files.
6. Added -Force flag to tools/decrypt_psk.ps1 and improved tools/dump_dpapi_blob.py distro hints.
7. Created docs/psk-extraction.md and tools/README.md with clear instructions for dual-boot and Linux-only systems.

**Blocked by:** None.

**Status:** closed

**Verdict:** Closed (software-complete, test suite 356/356 green). Closes external issues #10 and #11.
