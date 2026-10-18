/* Goodix 5e0a image normalization. LGPL-2.1-or-later.
 * Copyright (C) 2026 The libfprint Goodix 5e0a contributors
 */
#pragma once

#include <glib.h>
#include <math.h>
#include <string.h>
#include "goodix5e0a.h"

/* Mean over a (2r+1)x(2r+1) window, clipped at the frame edges. */
static void
goodix5e0a_box_mean (const float *in, float *out, int W, int H, int r)
{
  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++)
      {
        float sum = 0.0f;
        guint count = 0;
        for (int yy = MAX (0, y - r); yy <= MIN (H - 1, y + r); yy++)
          for (int xx = MAX (0, x - r); xx <= MIN (W - 1, x + r); xx++)
            {
              sum += in[yy * W + xx];
              count++;
            }
        out[y * W + x] = sum / count;
      }
}

static gboolean
goodix5e0a_normalize_raw_frame (const guint16 *pix, guint8 *out_norm,
                              float *out_min, float *out_max)
{
  if (!pix || !out_norm)
    return FALSE;

  const int W = GOODIX_5E0A_WIDTH, H = GOODIX_5E0A_HEIGHT;
  guint active = 0;

  for (int i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    if (pix[i] > 30)
      active++;

  if (active < 64)
    {
      memset (out_norm, 0, GOODIX_5E0A_FRAME_SIZE);
      return FALSE;
    }

  /* Issue #12: band-pass instead of a pure 3x3 high-pass. Some units carry
   * strong pixel-to-pixel noise that a 3x3 residual keeps in full while the
   * ~8-10 px ridge period mostly cancels, so smooth first (noise) and subtract
   * an 11x11 background (illumination), then scale to a fixed residual RMS. */
  g_autofree float *raw = g_new (float, GOODIX_5E0A_FRAME_SIZE);
  g_autofree float *smooth = g_new (float, GOODIX_5E0A_FRAME_SIZE);
  g_autofree float *background = g_new (float, GOODIX_5E0A_FRAME_SIZE);
  g_autofree float *residual = g_new (float, GOODIX_5E0A_FRAME_SIZE);
  float residual_min = G_MAXFLOAT, residual_max = -G_MAXFLOAT;

  for (int i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    raw[i] = pix[i];
  goodix5e0a_box_mean (raw, smooth, W, H, GOODIX_5E0A_BANDPASS_SMOOTH_RADIUS);
  goodix5e0a_box_mean (smooth, background, W, H, GOODIX_5E0A_BANDPASS_BACKGROUND_RADIUS);

  double sum_sq = 0.0;
  for (int i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    {
      float value = smooth[i] - background[i];
      residual[i] = value;
      sum_sq += (double) value * value;
      residual_min = MIN (residual_min, value);
      residual_max = MAX (residual_max, value);
    }

  float residual_range = residual_max - residual_min;
  float residual_rms = sqrtf ((float) (sum_sq / GOODIX_5E0A_FRAME_SIZE));
  if (out_min)
    *out_min = residual_min;
  if (out_max)
    *out_max = residual_max;

  if (residual_range < 1.0f || residual_rms < 0.5f)
    {
      memset (out_norm, 0, GOODIX_5E0A_FRAME_SIZE);
      return FALSE;
    }

  float gain = GOODIX_5E0A_BANDPASS_TARGET_RMS / residual_rms;
  for (guint i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    {
      int value = (int) roundf (GOODIX_5E0A_NORMALIZE_MIDPOINT + residual[i] * gain);
      out_norm[i] = (guint8) CLAMP (value, 0, 255);
    }
  return TRUE;
}
