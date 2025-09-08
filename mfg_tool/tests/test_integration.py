#!/usr/bin/env python3

# Copyright 2025 Espressif Systems (Shanghai) PTE LTD
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

"""
Integration test suite for esp-matter-mfg-tool
"""

import json
import os
import shutil
import shlex
import logging
from pathlib import Path
from typing import List, Optional, Tuple

from sources.cert_utils import load_cert_from_file, extract_common_name
from .utils import run_command, parse_mfg_tool_output, Config, ParsedOutput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestEspMatterMfgToolIntegration:
    """Integration test class for esp-matter-mfg-tool functionality"""

    @classmethod
    def setup_class(cls):
        """Set up test environment"""
        cls.test_data_dir = Path("test_data/")
        cls.output_dir = Path("out/")

        # Add test_data directory to PATH for chip-cert command
        os.environ["PATH"] = f"{os.environ.get('PATH', '')}:{cls.test_data_dir.absolute()}"

    def teardown_method(self):
        """Clean up after each test"""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)

    def _validate_certificates_with_chip_cert(self, parsed_output: List[ParsedOutput]):
        """
        Validate certificates using chip-cert (skip if not available)

        Args:
            parsed_output: Parsed output of the esp-matter-mfg-tool command

        Returns:
            None
        """
        assert len(parsed_output) > 0, "Could not find output path, Certificates not generated"

        for output in parsed_output:
            dac_cert = Path(output.dac_cert)
            pai_cert = Path(output.pai_cert)
            paa_cert = Path(f"{self.test_data_dir}/Chip-Test-PAA-NoVID-Cert.pem")
            assert all([dac_cert.exists(), pai_cert.exists(), paa_cert.exists()]), "Certificate files not generated"

            # Run chip-cert validation
            cert_cmd = f"chip-cert validate-att-cert -d {dac_cert} -i {pai_cert} -a {paa_cert}"
            result = run_command(cert_cmd)
            assert result.returncode == 0, f"Certificate validation failed: {result.stderr}"
            logger.info("Certificate chain validated successfully")

    def _validate_no_bin_files(self, output: str):
        """
        Validate that no binary partition files are generated

        Args:
            output: Output of the esp-matter-mfg-tool command

        Returns:
            None
        """
        assert "*-partition.bin" not in output, "partition.bin files generated but expected to be skipped"
        logger.info("No partition.bin files generated")

    def _validate_output_paths_with_dac_cert_common_name(self, parsed_output: List[ParsedOutput], present: bool = True):
        """
        Validate that output paths match DAC certificate common names

        Args:
            parsed_output: Parsed output of the esp-matter-mfg-tool command
            present: Whether the DAC certificate common name should be present in the output path

        Returns:
            None
        """
        for output in parsed_output:
            dac_cert = load_cert_from_file(output.dac_cert)
            cn = extract_common_name(dac_cert.subject)
            if present:
                assert cn in output.out_path, "DAC certificate common name not found in output path"
            else:
                assert cn not in output.out_path, "DAC certificate common name found in output path"
        logger.info("Output paths validated successfully")

    def _validate_command_output(self, output: str, config: Config):
        """
        Validate command output based on config flags

        Args:
            output: Output of the esp-matter-mfg-tool command
            config: Configuration for the test case

        Returns:
            None
        """
        assert config.expected_output in output, f"Expected output not found: {config.expected_output}"

        if config.validate_no_bin:
            self._validate_no_bin_files(output)

        parsed_output = parse_mfg_tool_output(output)

        if config.validate_csv_quoting:
            self._validate_csv_quoting(config.command)

        if config.validate_cert:
            self._validate_certificates_with_chip_cert(parsed_output)
        if config.validate_cn_in_path or config.validate_cn_not_in_path:
            self._validate_output_paths_with_dac_cert_common_name(parsed_output, True if config.validate_cn_in_path else False)

    def _load_test_data(self) -> List[Config]:
        """
        Load test configurations from JSON file

        Args:
            None

        Returns:
            List[Config]: List of test configurations
        """
        test_data_file = Path(f"{self.test_data_dir}/test_integration_inputs.json")
        with open(test_data_file, "r") as f:
            data = json.load(f)

        return [Config.from_dict(test) for test in data.get("tests", [])]

    def _extract_outdir(self, cmd: str) -> Optional[str]:
        """
        Get the outdir from the command if present
        """
        args = shlex.split(cmd)
        for i, arg in enumerate(args):
            if arg == "--outdir" and i + 1 < len(args):
                return args[i + 1]
            elif arg.startswith("--outdir="):
                return arg.split("=", 1)[1]
        return None

    def _extract_vid_pid(self, cmd: str) -> Optional[Tuple[str, str]]:
        """
        Get the vid and pid string from the command if present
        """
        args = shlex.split(cmd)
        vid, pid = None, None
        for i, arg in enumerate(args):
            if (arg == "-v" or arg == "--vendor-id") and i + 1 < len(args):
                vid = args[i + 1]
            elif (arg == "-p" or arg == "--product-id") and i + 1 < len(args):
                pid = args[i + 1]
        return vid, pid

    def _extract_vid_pid_str(self, cmd: str) -> str:
        vid, pid = self._extract_vid_pid(cmd)
        return f"{int(vid, 16):04x}_{int(pid, 16):04x}"

    def _run_single_test(self, test_num: int, config: Config):
        """
        Run a single test case

        Args:
            test_num: Test number
            config: Configuration for the test case

        Returns:
            None
        """
        logger.info(f"\n\n--- Test {test_num} - {config.description} ---")
        logger.info(f"Command: {config.command}")
        logger.info(f"Expected output: {config.expected_output}")

        # use the outdir from the command if present, else fallback to default outdir
        outdir_in_cmd = self._extract_outdir(config.command)
        vid_pid_str = self._extract_vid_pid_str(config.command)
        self.output_dir = Path(outdir_in_cmd) if outdir_in_cmd else Path(f"out/{vid_pid_str}")

        # Run the command
        result = run_command(config.command)
        output = result.stdout + result.stderr

        # Validate output
        self._validate_command_output(output, config)

        logger.info(f"Test {test_num} passed successfully")

    def test_esp_matter_mfg_tool_parametrized(self):
        """Run all parameterized test cases for esp-matter-mfg-tool"""
        test_configs = self._load_test_data()

        for test_num, config in enumerate(test_configs, 1):
            self._run_single_test(test_num, config)
            self.teardown_method()

    def _validate_csv_quoting(self, command: str):
        import csv

        outdir_in_cmd = self._extract_outdir(command)
        vid_pid_str = self._extract_vid_pid_str(command)
        out_dir = Path(outdir_in_cmd) if outdir_in_cmd else Path(f"out/{vid_pid_str}")

        master_csv = Path(out_dir) / "staging" / "master.csv"
        assert master_csv.exists(), "master.csv not found"

        with open(master_csv, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                assert "Test Vendor,LLC" == row['vendor-name'], "Vendor name should be quoted"
