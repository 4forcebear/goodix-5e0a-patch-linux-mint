# Hardware validation: Realme Book 14 i5

**Result:** fingerprint capture, enrollment, and verification work on the
Goodix `27c6:5e0a` sensor under Linux Mint.

## Observed

- Milan enrollment completed at 12 accepted touches and saved a right-index
  template.
- Driver build #121 returned `verify-match` for that enrolled finger.
- `sudo`'s PAM stack displayed the instruction to place a finger
  on the reader.
- The graphical login screen can still require the account password when the
  home directory is protected by eCryptfs. Keep password login available.

## Driver behavior in the verified revision

- Reads and validates the sensor's 64-byte OTP calibration at activation.
- Applies per-device calibration to the in-memory sensor configuration and
  image capture parameters.
- Requires 12 Milan-accepted enrollment samples and checks the enrollment
  count remains consistent when Milan rejects an image.
- During verification, checks each strong frame in the scan burst with Milan;
  the default Milan match decision is used without a custom percentage gate.

## Limits of this result

This is a hardware confirmation on one Realme Book 14 i5. The `sudo` prompt
was observed; successful completion of the sudo authentication was not
recorded. Other laptop units may have a different sensor PSK and need the
per-device key setup described in [PSK extraction](psk-extraction.md).
