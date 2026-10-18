# Reuse the driver's pinned source, patch, Meson flags and dependencies.
{ pkgs ? import <nixpkgs> {} }:
let
  driver = pkgs.callPackage ../libfprint-goodix.nix {};
in driver.overrideAttrs (old: {
  pname = "goodix-native-harness";
  postBuild = (old.postBuild or "") + ''
    $CC -o test_ssm_teardown \
      ${../tests/tier5_adversarial/test_ssm_teardown_c.c} \
      ../tests/test-device-fake.c \
      -I.. -I../libfprint -I../tests -I. -Ilibfprint \
      libfprint/libfprint-private.a libfprint/libnbis.a \
      -Llibfprint -Wl,-rpath,$out/lib -lfprint-2 \
      $(pkg-config --cflags --libs gio-2.0 gusb) -lm
    $CC -Wall -Wextra -Werror -o test_protocol \
      ${../tests/tier5_adversarial/test_protocol_c.c} \
      ../libfprint/drivers/goodixtls/goodix_proto.c \
      -I../libfprint/drivers/goodixtls $(pkg-config --cflags --libs gio-2.0)
    $CC -o test_milan_raster ${../tests/tier5_adversarial/test_milan_raster_c.c} \
      -I.. -DGOODIX_MILAN_C_INCLUDE='"libfprint/drivers/goodixtls/goodix_milan.c"' \
      $(pkg-config --cflags --libs glib-2.0) -lm
  '';
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    LD_LIBRARY_PATH="$PWD/libfprint" ./test_ssm_teardown
    ./test_protocol
    ./test_milan_raster
    runHook postCheck
  '';
  postInstall = (old.postInstall or "") + ''
    install -Dm755 test_ssm_teardown "$out/bin/test_ssm_teardown"
    install -Dm755 test_protocol "$out/bin/test_protocol"
    install -Dm755 test_milan_raster "$out/bin/test_milan_raster"
  '';
})
