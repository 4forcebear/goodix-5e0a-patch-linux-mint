/* Per-unit ChicagoH calibration, derived from Wbdi.dll 3.0.141.150.
 * OTP is read-only. Updates apply to the volatile MCU configuration. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint8_t
goodix5e0a_otp_crc (const uint8_t *bytes, size_t length)
{
  uint8_t crc = 0;
  for (size_t i = 0; i < length; i++) {
    crc ^= bytes[i];
    for (unsigned bit = 0; bit < 8; bit++)
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 7) : (uint8_t)(crc << 1);
  }
  return (uint8_t)~crc;
}

static int
goodix5e0a_calibrate (const uint8_t *otp, size_t length,
                       uint8_t config[256], uint8_t capture[10],
                       uint16_t *out_tcode)
{
  if (!otp || !config || !capture || !out_tcode || length != 64) return 0;
  uint8_t cp[15], ft[19], mt[27];
  memcpy(cp, otp, 11); memcpy(cp + 11, otp + 36, 4);
  memcpy(ft, otp + 11, 9); ft[9] = otp[28];
  memcpy(ft + 10, otp + 50, 4); memcpy(ft + 14, otp + 56, 4); ft[18] = otp[62];
  memcpy(mt, otp + 20, 8); memcpy(mt + 8, otp + 29, 7);
  memcpy(mt + 15, otp + 40, 10); memcpy(mt + 25, otp + 54, 2);
  if (goodix5e0a_otp_crc(cp, sizeof cp) != otp[60] ||
      goodix5e0a_otp_crc(ft, sizeof ft) != otp[61] ||
      goodix5e0a_otp_crc(mt, sizeof mt) != otp[63] ||
      goodix5e0a_otp_crc(otp + 50, 4) != otp[62] ||
      goodix5e0a_otp_crc(otp + 46, 4) != otp[22] ||
      memcmp(otp + 46, otp + 50, 4) != 0) return 0;
  uint8_t t = 0, complement = (uint8_t)~otp[43];
  if (otp[42] && otp[42] == complement) t = otp[42];
  else if (otp[45] && otp[45] == complement) t = otp[45];
  else if (otp[42] && otp[42] == otp[45]) t = otp[42];
  if (!t) return 0;
  uint16_t tcode = ((t >> 4) + 1) * 16 + 64;
  /* ModifyImageTcode walks ONLY config[9] .. config[9]+config[10]. */
  unsigned begin = config[9], end = begin + config[10], slot = 256;
  if (begin < 16 || end > 254 || (end - begin) % 4) return 0;
  for (unsigned i = begin; i + 4 <= end; i += 4)
    if (config[i] == 0x5c && config[i + 1] == 0) { slot = i; break; }
  if (slot == 256) return 0;
  config[slot + 2] = tcode & 0xff;
  config[slot + 3] = tcode >> 8;
  uint16_t checksum = 0xa5a5;
  for (unsigned i = 0; i < 254; i += 2)
    checksum += config[i] | ((uint16_t)config[i + 1] << 8);
  checksum = (uint16_t)(0 - checksum);
  config[254] = checksum & 0xff; config[255] = checksum >> 8;
  capture[0] = 5; capture[1] = 0;
  for (unsigned i = 0; i < 4; i++) {
    capture[2 + 2*i] = otp[50 + i]; capture[3 + 2*i] = 0;
  }
  *out_tcode = tcode;
  return 1;
}
