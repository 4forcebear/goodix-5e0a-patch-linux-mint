/* Compile the real bridge; replace only algorithm exports. No DLL or USB. */
#ifndef GOODIX_MILAN_C_INCLUDE
#define GOODIX_MILAN_C_INCLUDE "../../libfprint-driver/goodix_milan.c"
#endif
#include GOODIX_MILAN_C_INCLUDE

static guint8 canonical[64 * 80];
static guint image_calls, deletes;
static gboolean reject;

static void check_image (GoodixImage *image)
{
  g_assert_cmpint (image->width, ==, 80);
  g_assert_cmpint (image->height, ==, 64);
  g_assert_cmpint (image->bits, ==, 8);
  g_assert_cmpint (image->channels, ==, 1);
  g_assert_cmpint (image->frame_count, ==, 1);
  g_assert_cmpuint (image->sensor_type, ==, 10);
  g_assert_true (image->data != canonical);
  for (int row = 0; row < 64; row++)
    for (int col = 0; col < 80; col++)
      g_assert_cmpuint (image->data[row * 80 + col], ==,
                       (row * 3 + col * 5) % 256);
  image_calls++;
}

static int MS quality (GoodixImage *image, u32 *out)
{
  check_image (image);
  image->quality = 71;
  image->overlap = 96;
  return 0;
}

static int MS enroll (void *ctx, GoodixImage *image, void *a, void *b, u8 c, u32 *out)
{
  check_image (image);
  return 0;
}

static int MS unpack (const void *data, int len, void *optional, void **out)
{
  *out = (void *) data;
  return 0;
}

static int MS delete_template (void *template)
{
  deletes++;
  return 0;
}

static int MS identify (GoodixImage *image, void *a, void **templates, int count,
                        int *idx, int *score, u32 *details, int b, int c, void *d, int e)
{
  check_image (image);
  *idx = reject ? -1 : count - 1;
  *score = reject ? -7 : 35;
  return 0;
}

static void test_all_entry_points (void)
{
  for (int y = 0; y < 80; y++)
    for (int x = 0; x < 64; x++)
      canonical[y * 64 + x] = (x * 3 + y * 5) % 256;
  g_milan_available = TRUE;
  m_getQuality = quality;
  m_enrolAddImage = enroll;
  m_templateUnPack = unpack;
  m_templateDelete = delete_template;
  m_identifyImage = identify;

  guint q, overlap;
  g_assert_cmpuint (goodix_milan_frame_quality (canonical, 64, 80, &q, &overlap), ==, (71 << 8) | 96);
  g_assert_cmpuint (q, ==, 71);
  g_assert_cmpuint (overlap, ==, 96);
  guint8 ctx[16] = {0};
  g_assert_cmpint (goodix_milan_enroll_add_image (ctx, canonical, 64, 80, NULL, NULL), ==, 0);

  const guint8 blob[] = {1, 2, 3};
  int score, idx;
  const guint8 *blobs[] = {blob, blob};
  size_t lens[] = {sizeof (blob), sizeof (blob)};
  g_assert_cmpint (goodix_milan_verify_image (canonical, 64, 80, blob, sizeof (blob), &score), ==, 1);
  g_assert_cmpint (score, ==, 35); /* Preserve the engine's positive-score gate. */
  g_assert_cmpint (goodix_milan_identify_image (canonical, 64, 80, blobs, lens, 2, &idx, &score), ==, 1);
  g_assert_cmpint (idx, ==, 1);
  g_assert_cmpint (score, ==, 35);
  reject = TRUE;
  g_assert_cmpint (goodix_milan_verify_image (canonical, 64, 80, blob, sizeof (blob), &score), ==, 0);
  g_assert_cmpint (score, ==, 0);
  g_assert_cmpint (goodix_milan_identify_image (canonical, 64, 80, blobs, lens, 2, &idx, &score), ==, 0);
  g_assert_cmpint (idx, ==, -1);
  g_assert_cmpint (score, ==, 0);
  g_assert_cmpuint (image_calls, ==, 6);
  g_assert_cmpuint (deletes, ==, 6);

  /* Invalid geometry must not call an algorithm export. A gallery failure
   * after one successful unpack must free it without touching image storage. */
  g_assert_cmpuint (goodix_milan_frame_quality (canonical, 80, 64, NULL, NULL), ==, 0);
  g_assert_cmpint (goodix_milan_enroll_add_image (ctx, canonical, 80, 64, NULL, NULL), ==, -1);
  g_assert_cmpint (goodix_milan_verify_image (canonical, 80, 64, blob, sizeof (blob), NULL), ==, 0);
  g_assert_cmpint (goodix_milan_identify_image (canonical, 80, 64, blobs, lens, 2, &idx, &score), ==, 0);
  blobs[1] = NULL;
  g_test_expect_message (NULL, G_LOG_LEVEL_WARNING, "*gallery templateUnPack failed*");
  g_assert_cmpint (goodix_milan_identify_image (canonical, 64, 80, blobs, lens, 2, &idx, &score), ==, 0);
  g_test_assert_expected_messages ();
  g_assert_cmpuint (image_calls, ==, 6);
  g_assert_cmpuint (deletes, ==, 7);
  for (int y = 0; y < 80; y++)
    for (int x = 0; x < 64; x++)
      g_assert_cmpuint (canonical[y * 64 + x], ==, (x * 3 + y * 5) % 256);
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix/milan/native-raster", test_all_entry_points);
  return g_test_run ();
}
