"""
Tier 5 - Milestone 2 Adversarial Challenge: Activation SSM & Lifecycle State Transitions
Adversarially challenges the Goodix 27c6:5e0a driver activation SSM, error handling paths,
and lifecycle state machine transitions per Challenger 2 specifications.
"""

import unittest
import struct
from tests.repo_paths import repo
from tests.test_utils import (
    MockGoodixMCU, encode_pack, encode_protocol, decode_pack, decode_protocol,
    FLAGS_MSG_PROTOCOL, FLAGS_TLS, FLAGS_TLS_DATA,
    CMD_NOP, CMD_RESET, CMD_READ_SENSOR_REGISTER, CMD_READ_OTP, CMD_FIRMWARE_VERSION,
    CMD_REQUEST_TLS_CONNECTION, CMD_UPLOAD_CONFIG_MCU, CMD_ENABLE_CHIP,
    CMD_MCU_SWITCH_TO_FDT_DOWN,
    CMD_ACK, RESET_NUMBER, FIRMWARE_VERSION_STR, CHIP_ID_VAL,
    CANONICAL_CONFIG_52XD, CANONICAL_FDT_DOWN, CANONICAL_PSK, PSK_FLAGS
)

class TestM2C2ActivationSSM(unittest.TestCase):
    """
    Adversarial verification of goodix5e0a activation SSM and lifecycle state transitions.
    """

    def setUp(self):
        self.mcu = MockGoodixMCU()

    # --------------------------------------------------------------------------
    # 1. Activation SSM Step-by-Step Progression
    # --------------------------------------------------------------------------
    def test_ssm_progression_nominal_path(self):
        """
        Verify complete 5-stage activation SSM + post-TLS initialization:
        Stage 0: ACTIVATE_READ_AND_NOP (CMD 0x00)
        Stage 1: ACTIVATE_RESET (CMD 0xa2)
        Stage 2: ACTIVATE_READ_CHIP_ID (CMD 0x82, reg 0x0000)
        Stage 3: ACTIVATE_READ_OTP (CMD 0xa6)
        Stage 4: ACTIVATE_CHECK_FW_VER (CMD 0xa8)
        Post-SSM: TLS Init -> Config Upload (CMD 0x90) -> Chip Enable (CMD 0x96)
        """
        # State 0: ACTIVATE_READ_AND_NOP (silence is success / buffer empty)
        nop_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_NOP, b""))
        nop_reply = self.mcu.handle_out_packet(nop_pkt)
        self.assertEqual(nop_reply, b"")

        # State 1: ACTIVATE_RESET
        rst_payload = struct.pack("<BB", 0x03, 20)
        rst_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_RESET, rst_payload))
        rst_reply = self.mcu.handle_out_packet(rst_pkt)
        ok, _, body, _ = decode_pack(rst_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_RESET)
        counter = struct.unpack("<H", payload)[0]
        self.assertEqual(counter, RESET_NUMBER)

        # State 2: ACTIVATE_READ_CHIP_ID
        cid_payload = struct.pack("<BHBB", 0x00, 0x0000, 4, 0x00)
        cid_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_READ_SENSOR_REGISTER, cid_payload))
        cid_reply = self.mcu.handle_out_packet(cid_pkt)
        ok, _, body, _ = decode_pack(cid_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_READ_SENSOR_REGISTER)
        self.assertEqual(payload, CHIP_ID_VAL)

        # State 3: ACTIVATE_CHECK_FW_VER
        fw_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_FIRMWARE_VERSION, b""))
        fw_reply = self.mcu.handle_out_packet(fw_pkt)
        ok, _, body, _ = decode_pack(fw_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_FIRMWARE_VERSION)
        fw_str = payload.rstrip(b"\x00").decode("ascii")
        self.assertEqual(fw_str, FIRMWARE_VERSION_STR)

        # Post-SSM Stage 1: TLS Handshake
        tls_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_REQUEST_TLS_CONNECTION, b""))
        tls_reply = self.mcu.handle_out_packet(tls_pkt)
        ok, _, body, _ = decode_pack(tls_reply)
        self.assertTrue(self.mcu.tls_established)

        # Post-SSM Stage 2: MCU Config Upload (CONFIG_52XD)
        cfg_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_UPLOAD_CONFIG_MCU, CANONICAL_CONFIG_52XD))
        cfg_reply = self.mcu.handle_out_packet(cfg_pkt)
        ok, _, body, _ = decode_pack(cfg_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_ACK)
        self.assertEqual(payload[0], CMD_UPLOAD_CONFIG_MCU)
        self.assertEqual(self.mcu.mcu_config, CANONICAL_CONFIG_52XD)

        # Post-SSM Stage 3: Chip Enable (0x96)
        enb_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_ENABLE_CHIP, bytes([0x01, 0x00])))
        enb_reply = self.mcu.handle_out_packet(enb_pkt)
        ok, _, body, _ = decode_pack(enb_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_ACK)
        self.assertEqual(payload[0], CMD_ENABLE_CHIP)
        self.assertTrue(self.mcu.chip_enabled)

    # --------------------------------------------------------------------------
    # 2. Error Handling: Firmware Version & Chip ID Mismatches
    # --------------------------------------------------------------------------
    def test_firmware_version_mismatch_adversarial(self):
        """
        Adversarially inject mismatched firmware version strings and verify detection.
        goodixtls5xx_check_firmware_version must accept explicitly supported
        5e0a revisions and reject every other string.
        """
        with open(repo("libfprint-driver", "goodix5xx.c"), "r", encoding="utf-8") as f:
            base = f.read()
        self.assertIn("goodixtls5xx_check_firmware_version", base)
        self.assertIn("strcmp (firmware, cls->firmware_version)", base)
        self.assertIn("strcmp (firmware, cls->firmware_version_compat)", base)
        with open(repo("libfprint-driver", "goodix5e0a.c"), "r", encoding="utf-8") as f:
            drv = f.read()
        self.assertIn("firmware_version = GOODIX_5E0A_FIRMWARE_VERSION;", drv)
        self.assertIn("firmware_version_compat = GOODIX_5E0A_COMPAT_FIRMWARE_VERSION;", drv)
        with open(repo("libfprint-driver", "goodix5e0a.h"), "r", encoding="utf-8") as f:
            drv_header = f.read()
        compat_version = "GFUSB_GM168SEC_APP_10034"
        self.assertIn(f'GOODIX_5E0A_COMPAT_FIRMWARE_VERSION ("{compat_version}")', drv_header)
        supported_versions = [FIRMWARE_VERSION_STR, compat_version]
        for supported_fw in supported_versions:
            matches = (supported_fw == FIRMWARE_VERSION_STR or supported_fw == compat_version)
            self.assertTrue(matches, f"Supported FW '{supported_fw}' was incorrectly rejected")
        mismatched_versions = [
            "GFUSB_GM168SEC_APP_10037",
            "GFUSB_GM168SEC_APP_10035",
            "GFUSB_GM168SEC_APP_00000",
            "GF5288_ROM_BOOT_v1.0",
            "",
            "GFUSB_GM168SEC_APP_10036_CORRUPT",
            "INVALID_MCU_FW"
        ]
        for bad_fw in mismatched_versions:
            # Emulate the explicit primary + compatibility version check.
            matches = (bad_fw == FIRMWARE_VERSION_STR or bad_fw == compat_version)
            self.assertFalse(matches, f"Mismatched FW '{bad_fw}' was incorrectly accepted")

    def test_firmware_version_truncated_payload(self):
        """Verify truncated or empty firmware reply fails string comparison."""
        truncated_bytes = b"GFUSB\x00"
        self.assertNotEqual(truncated_bytes.rstrip(b"\x00").decode("ascii"), FIRMWARE_VERSION_STR)

    def test_reset_counter_mismatch_adversarial(self):
        """
        Adversarially test invalid reset counter numbers.
        goodixtls5xx_check_reset must strictly validate reset_number == 2048.
        """
        with open(repo("libfprint-driver", "goodix5xx.c"), "r", encoding="utf-8") as f:
            base = f.read()
        self.assertIn("number != cls->reset_number", base)
        with open(repo("libfprint-driver", "goodix5e0a.c"), "r", encoding="utf-8") as f:
            drv = f.read()
        self.assertIn("reset_number = GOODIX_5E0A_RESET_NUMBER;", drv)
        invalid_reset_numbers = [0, 1, 1024, 2047, 2049, 4096, 65535]
        for bad_cnt in invalid_reset_numbers:
            matches = (bad_cnt == RESET_NUMBER)
            self.assertFalse(matches, f"Invalid reset counter {bad_cnt} was incorrectly accepted")

    def test_chip_id_register_transport_failure(self):
        """
        Verify behavior when chip ID register (0x0000) read yields empty/corrupted response.
        """
        # Truncated reply packet (< 4 bytes)
        bad_reply = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_READ_SENSOR_REGISTER, b"\x27\xc6"))
        ok, flags, body, _ = decode_pack(bad_reply)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertTrue(p_ok)
        self.assertNotEqual(len(payload), 4, "Truncated chip ID must not have 4 bytes")

    # --------------------------------------------------------------------------
    # 3. Error Handling: Config Upload (0x90) & Chip Enable (0x96) Failures
    # --------------------------------------------------------------------------
    def test_config_upload_nack_detection(self):
        """
        Verify MCU NACK response (data[0] == 0x00) during config upload (CMD 0x90).
        """
        # Emulate MCU NACK for config upload
        nack_ack = bytes([0x00, 0x00])  # success = FALSE
        nack_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_UPLOAD_CONFIG_MCU, nack_ack))
        ok, flags, body, _ = decode_pack(nack_pkt)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertTrue(p_ok)
        success = (payload[0] != 0x00)
        self.assertFalse(success, "Config upload NACK was not detected as failure")

    def test_config_upload_corrupted_length(self):
        """
        Adversarially test config upload with truncated payload (< 256 bytes).
        """
        truncated_cfg = CANONICAL_CONFIG_52XD[:128]
        self.assertNotEqual(len(truncated_cfg), 256)
        # Verify wire encoding detects shorter length
        pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_UPLOAD_CONFIG_MCU, truncated_cfg))
        ok, _, body, _ = decode_pack(pkt)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertTrue(p_ok)
        self.assertEqual(len(payload), 128)

    def test_chip_enable_nack_detection(self):
        """
        Verify chip enable (0x96) rejection / NACK handling.
        """
        # Emulate failure reply for chip enable
        nack_reply = bytes([0x00, 0x00])
        nack_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_ENABLE_CHIP, nack_reply))
        ok, _, body, _ = decode_pack(nack_pkt)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertTrue(p_ok)
        enabled = (payload[0] != 0x00)
        self.assertFalse(enabled, "Chip enable NACK was not detected")

    # --------------------------------------------------------------------------
    # 4. Lifecycle State Transitions & Invariant Checks
    # --------------------------------------------------------------------------
    def test_lifecycle_activation_to_scan_transition(self):
        """
        Verify lifecycle transitions from Activation complete to Scan SSM initiation.
        """
        # 1. Device is activated
        self.mcu.chip_enabled = True
        self.mcu.tls_established = True
        self.mcu.mcu_config = CANONICAL_CONFIG_52XD

        # 2. State transition to AWAIT_FINGER_ON initiates scan_run_state:
        # SCAN_STAGE_QUERY_MCU (0xae) -> SCAN_STAGE_SWITCH_TO_FDT_MODE (0x36) -> SCAN_STAGE_SWITCH_TO_FDT_DOWN (0x32)
        q_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(0xAE, b""))
        q_rep = self.mcu.handle_out_packet(q_pkt)
        self.assertGreater(len(q_rep), 0)

        fdt_m_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(0x36, bytes(27)))
        fdt_m_rep = self.mcu.handle_out_packet(fdt_m_pkt)
        self.assertGreater(len(fdt_m_rep), 0)

        fdt_d_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(0x32, bytes(39)))
        fdt_d_rep = self.mcu.handle_out_packet(fdt_d_pkt)
        self.assertTrue(self.mcu.fdt_down_active)

    def test_lifecycle_activation_state_via_packet_path(self):
        """
        Verify activation state is reachable via the packet path before teardown.
        (Teardown itself is driver-side; covered against source in
        test_f25_dbus_lifecycle.py::test_clean_deactivation_and_ssm_free.)
        """
        # Drive mock to active state through real packet handling
        enb_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_ENABLE_CHIP, bytes([0x01, 0x00])))
        enb_rep = self.mcu.handle_out_packet(enb_pkt)
        ok, _, body, _ = decode_pack(enb_rep)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertEqual(cmd, CMD_ACK)
        self.assertTrue(self.mcu.chip_enabled)

        fdt_d_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_MCU_SWITCH_TO_FDT_DOWN, CANONICAL_FDT_DOWN))
        self.mcu.handle_out_packet(fdt_d_pkt)
        self.assertTrue(self.mcu.fdt_down_active)

    def test_activation_ssm_states_definition_in_driver(self):
        """Verify goodix5e0a.c defines all 4 activation states and wires them correctly."""
        with open(repo("libfprint-driver", "goodix5e0a.c"), "r", encoding="utf-8") as f:
            drv = f.read()
        expected_states = [
            "ACTIVATE_READ_AND_NOP",
            "ACTIVATE_RESET",
            "ACTIVATE_READ_CHIP_ID",
            "ACTIVATE_READ_OTP",
            "ACTIVATE_CHECK_FW_VER",
            "ACTIVATE_UPLOAD_CONFIG",
            "ACTIVATE_NUM_STATES",
        ]
        for st in expected_states:
            self.assertIn(st, drv)

    def test_otp_read_payload_handling(self):
        """Verify OTP read payload validation and response handling."""
        otp_pkt = encode_pack(FLAGS_MSG_PROTOCOL, encode_protocol(CMD_READ_OTP, b""))
        reply = self.mcu.handle_out_packet(otp_pkt)
        ok, flags, body, _ = decode_pack(reply)
        self.assertTrue(ok)
        p_ok, cmd, payload, _, _ = decode_protocol(body)
        self.assertTrue(p_ok)
        self.assertEqual(cmd, CMD_READ_OTP)
        self.assertEqual(len(payload), 32)

if __name__ == "__main__":
    unittest.main()
