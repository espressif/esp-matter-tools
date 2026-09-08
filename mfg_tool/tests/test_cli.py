#!/usr/bin/env python3

# Copyright 2026 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for sources/cli.py — CLI option parsing, validation, and MultiValueOption."""

import subprocess
import sys
from pathlib import Path

import pytest
from unittest.mock import patch
from click.testing import CliRunner
from sources.cli import main


BASE_ARGS = ["-v", "0xFFF2", "-p", "0x8001"]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def mock_main_internal():
    """Prevent actual partition generation in all CLI unit tests."""
    with patch("sources.cli.main_internal") as mock:
        yield mock


def get_ns(mock_main_internal):
    """Return the SimpleNamespace passed to main_internal."""
    return mock_main_internal.call_args[0][0]


class TestMultiValueOption:
    """
    Smoke tests for MultiValueOption.
    These catch breakage if Click's private internals (_long_opt, _short_opt, .process) change.
    """

    def test_two_space_separated_values(self, runner, mock_main_internal):
        result = runner.invoke(
            main, BASE_ARGS + ["--calendar-types", "Buddhist", "Gregorian"]
        )
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).calendar_types == ["Buddhist", "Gregorian"]

    def test_three_space_separated_values(self, runner, mock_main_internal):
        result = runner.invoke(
            main, BASE_ARGS + ["--locales", "en-US", "en-GB", "fr-FR"]
        )
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).locales == ["en-US", "en-GB", "fr-FR"]

    def test_single_value(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--calendar-types", "Gregorian"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).calendar_types == ["Gregorian"]

    def test_stops_consuming_at_next_option(self, runner, mock_main_internal):
        result = runner.invoke(
            main, BASE_ARGS + ["--calendar-types", "Buddhist", "Gregorian", "--no-bin"]
        )
        assert result.exit_code == 0
        ns = get_ns(mock_main_internal)
        assert ns.calendar_types == ["Buddhist", "Gregorian"]
        assert ns.generate_bin is False

    def test_fixed_labels(self, runner, mock_main_internal):
        result = runner.invoke(
            main,
            BASE_ARGS + ["--fixed-labels", "0/orientation/up", "1/orientation/down"],
        )
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).fixed_labels == [
            "0/orientation/up",
            "1/orientation/down",
        ]

    def test_supported_modes(self, runner, mock_main_internal):
        result = runner.invoke(
            main, BASE_ARGS + ["--supported-modes", "0/label1/1", "1/label2/1"]
        )
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).supported_modes == [
            "0/label1/1",
            "1/label2/1",
        ]

    def test_calendar_types_invalid_value_rejected(self, runner):
        result = runner.invoke(main, BASE_ARGS + ["--calendar-types", "NotAType"])
        assert result.exit_code != 0
        assert "NotAType" in result.output

    def test_calendar_types_all_valid_values_accepted(self, runner, mock_main_internal):
        from sources.utils import CalendarTypes

        all_types = [ct.name for ct in CalendarTypes]
        result = runner.invoke(main, BASE_ARGS + ["--calendar-types"] + all_types)
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).calendar_types == all_types


class TestDiscoveryMode:
    def test_valid_ble(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-dm", "2"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discovery_mode == 2

    def test_valid_on_network(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-dm", "4"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discovery_mode == 4

    def test_valid_ble_and_on_network(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-dm", "6"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discovery_mode == 6

    def test_valid_hex_input(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-dm", "0x4"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discovery_mode == 4

    # Matter 1.6 (section 5.1.3.1, Table 60) adds Wi-Fi PAF (8), NFC (16) and
    # Thread (32) bits. Any combination of bits 1-5 (mask 0x3E) is valid.
    @pytest.mark.parametrize(
        "val, expected",
        [("8", 8), ("16", 16), ("32", 32), ("34", 34), ("0x3E", 0x3E)],
    )
    def test_valid_bitmask_values(self, runner, mock_main_internal, val, expected):
        result = runner.invoke(main, BASE_ARGS + ["-dm", val])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discovery_mode == expected

    # Invalid values are rejected: 0 advertises no transport, 1/3/5/7/0x3F set
    # reserved bit 0, and 64/0x40/255 set reserved bits 6-7.
    @pytest.mark.parametrize(
        "val", ["0", "1", "3", "5", "7", "0x3F", "64", "0x40", "255"]
    )
    def test_invalid_values_rejected(self, runner, val):
        result = runner.invoke(main, BASE_ARGS + ["-dm", val])
        assert result.exit_code != 0
        assert "not allowed" in result.output.lower()
        assert "2, 4, 8, 16, 32" in result.output


class TestCommissioningFlow:
    @pytest.mark.parametrize("val,expected", [("0", 0), ("1", 1), ("2", 2), ("0x1", 1)])
    def test_valid_values(self, runner, mock_main_internal, val, expected):
        result = runner.invoke(main, BASE_ARGS + ["-cf", val])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).commissioning_flow == expected

    @pytest.mark.parametrize("val", ["3", "4", "0x3"])
    def test_invalid_values_rejected(self, runner, val):
        result = runner.invoke(main, BASE_ARGS + ["-cf", val])
        assert result.exit_code != 0


class TestEfuseKeyId:
    @pytest.mark.parametrize("val", [-1, 0, 1, 5])
    def test_valid_range(self, runner, mock_main_internal, val):
        result = runner.invoke(main, BASE_ARGS + ["--efuse-key-id", str(val)])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).efuse_key_id == val

    def test_out_of_range_high(self, runner):
        result = runner.invoke(main, BASE_ARGS + ["--efuse-key-id", "6"])
        assert result.exit_code != 0
        assert "not in the range" in result.output

    def test_out_of_range_low(self, runner):
        result = runner.invoke(main, BASE_ARGS + ["--efuse-key-id", "-2"])
        assert result.exit_code != 0


class TestHexInput:
    """Ensures any_base_int correctly handles hex/octal/decimal for all int options."""

    def test_vendor_and_product_id_hex(self, runner, mock_main_internal):
        result = runner.invoke(main, ["-v", "0xFFF2", "-p", "0x8001"])
        assert result.exit_code == 0
        ns = get_ns(mock_main_internal)
        assert ns.vendor_id == 0xFFF2
        assert ns.product_id == 0x8001

    def test_vendor_and_product_id_decimal(self, runner, mock_main_internal):
        result = runner.invoke(main, ["-v", "100", "-p", "200"])
        assert result.exit_code == 0
        ns = get_ns(mock_main_internal)
        assert ns.vendor_id == 100
        assert ns.product_id == 200

    def test_size_hex(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-s", "0x6000"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).size == 0x6000

    def test_count_hex(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["-n", "0x3"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).count == 3

    def test_passcode_hex(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--passcode", "0x1344EF"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).passcode == 0x1344EF

    def test_discriminator_hex(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--discriminator", "0xF00"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).discriminator == 0xF00


class TestRequiredOptions:
    def test_missing_vendor_id(self, runner):
        result = runner.invoke(main, ["-p", "0x8001"])
        assert result.exit_code != 0
        assert "vendor-id" in result.output.lower()

    def test_missing_product_id(self, runner):
        result = runner.invoke(main, ["-v", "0xFFF2"])
        assert result.exit_code != 0
        assert "product-id" in result.output.lower()

    def test_missing_both(self, runner):
        result = runner.invoke(main, [])
        assert result.exit_code != 0


class TestMutualExclusion:
    def test_paa_and_pai_mutually_exclusive(self, runner):
        result = runner.invoke(main, BASE_ARGS + ["--paa", "--pai"])
        assert result.exit_code != 0


class TestDefaults:
    def test_default_values(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS)
        assert result.exit_code == 0
        ns = get_ns(mock_main_internal)
        assert ns.count == 1
        assert ns.size == 0x6000
        assert ns.discovery_mode == 2
        assert ns.commissioning_flow == 0
        assert ns.efuse_key_id == -1
        assert ns.generate_bin is True
        assert ns.log_level == "info"
        assert ns.target == "esp32"
        assert ns.lifetime == 36500
        assert ns.cn_prefix == "ESP32"

    def test_no_bin_flag(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--no-bin"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).generate_bin is False

    def test_encrypt_flag(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--encrypt"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).encrypt is True

    def test_log_level(self, runner, mock_main_internal):
        result = runner.invoke(main, BASE_ARGS + ["--log-level", "debug"])
        assert result.exit_code == 0
        assert get_ns(mock_main_internal).log_level == "debug"

    def test_invalid_log_level(self, runner):
        result = runner.invoke(main, BASE_ARGS + ["--log-level", "verbose"])
        assert result.exit_code != 0


class TestModuleInvocationCompatibility:
    # Rainmaker backend invokes the tool as: python3 -m sources.cli <args>
    # If this invocation path ever changes, either notify the Rainmaker backend
    # team or maintain backward compatibility so their pipeline is not broken.

    @pytest.fixture
    def mfg_tool_dir(self):
        return Path(__file__).parent.parent

    def _run(self, mfg_tool_dir, args):
        return subprocess.run(
            [sys.executable, "-m", "sources.cli"] + args,
            capture_output=True,
            text=True,
            cwd=mfg_tool_dir,
        )

    def test_help_exits_zero(self, mfg_tool_dir):
        result = self._run(mfg_tool_dir, ["--help"])
        assert result.returncode == 0

    def test_help_lists_required_options(self, mfg_tool_dir):
        result = self._run(mfg_tool_dir, ["--help"])
        output = result.stdout.lower()
        for opt in ["vendor-id", "product-id", "passcode", "discriminator", "count"]:
            assert opt in output, f"expected '{opt}' in --help output"

    def test_missing_required_args_exits_nonzero(self, mfg_tool_dir):
        result = self._run(mfg_tool_dir, [])
        assert result.returncode != 0

    def test_invalid_option_exits_nonzero(self, mfg_tool_dir):
        result = self._run(mfg_tool_dir, ["--nonexistent-option"])
        assert result.returncode != 0
