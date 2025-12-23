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

import logging
import os
import pytest
import tempfile
import shutil
import subprocess


logger = logging.getLogger(__name__)


class TestDMVIntegration:
    """Integration tests for the complete DMV tool workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")
        self.temp_dir = tempfile.mkdtemp()

        assert os.path.exists(
            self.test_data_dir
        ), f"Test data directory not found: {self.test_data_dir}"

    def teardown_method(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_command(self, command):
        """Run a command and capture output"""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=60
            )
            return result
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out: {e}")
            return e

    def validate_wildcard_logs(
        self,
        command,
        wildcard_file_path,
        expected_report_path,
        output_path,
        spec_version,
    ):
        """Validate wildcard logs and generate report"""
        result = self.run_command(command)
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert os.path.exists(output_path), f"Output file not found: {output_path}"
        with open(output_path, "r") as f:
            generated_report = f.read()
        with open(expected_report_path, "r") as f:
            expected_report = f.read()

        assert (
            generated_report == expected_report
        ), "Generated report does not match expected report"

    def test_wildcard_compliant_logs_validation(self):
        """Test validation of compliant wildcard logs generates expected report."""
        wildcard_file_path = os.path.join(
            self.test_data_dir, "wildcard_compliant_logs.txt"
        )
        expected_report_path = os.path.join(
            self.test_data_dir, "wildcard_compliant_report.txt"
        )
        output_path = os.path.join(
            self.temp_dir, "wildcard_compliant_report_generated.txt"
        )
        spec_version = "1.4.2"

        command = f"esp-matter-dm-validator check-conformance {wildcard_file_path} --spec-version {spec_version} --output-path {output_path}"
        self.validate_wildcard_logs(
            command, wildcard_file_path, expected_report_path, output_path, spec_version
        )

    def test_wildcard_missing_level_control_cluster_validation(self):
        """Test validation of logs with missing features generates expected report."""
        wildcard_file_path = os.path.join(
            self.test_data_dir, "wildcard_missing_level_control_cluster.txt"
        )
        expected_report_path = os.path.join(
            self.test_data_dir, "wildcard_missing_level_control_cluster_report.txt"
        )
        output_path = os.path.join(
            self.temp_dir, "wildcard_missing_level_control_cluster_report_generated.txt"
        )
        spec_version = "1.4.2"

        command = f"esp-matter-dm-validator check-conformance {wildcard_file_path} --spec-version {spec_version} --output-path {output_path}"
        self.validate_wildcard_logs(
            command, wildcard_file_path, expected_report_path, output_path, spec_version
        )

    def test_wildcard_missing_commands_validation(self):
        """Test validation of logs with missing commands generates expected report."""
        wildcard_file_path = os.path.join(
            self.test_data_dir, "wildcard_scenes_management_command_missing.txt"
        )
        expected_report_path = os.path.join(
            self.test_data_dir, "wildcard_scenes_management_command_missing_report.txt"
        )

        output_path = os.path.join(
            self.temp_dir,
            "wildcard_scenes_management_command_missing_report_generated.txt",
        )
        spec_version = "1.4.2"

        command = f"esp-matter-dm-validator check-conformance {wildcard_file_path} --spec-version {spec_version} --output-path {output_path}"
        self.validate_wildcard_logs(
            command, wildcard_file_path, expected_report_path, output_path, spec_version
        )

    def test_parse_wildcard_logs(self):
        """Test parsing of wildcard logs."""
        datamodel_logs_path = os.path.join(
            self.test_data_dir, "wildcard_compliant_logs.txt"
        )
        expected_report_path = os.path.join(self.test_data_dir, "parsed.json")
        output_path = os.path.join(self.temp_dir, "parsed.json")
        spec_version = "1.4.2"

        command = f"esp-matter-dm-validator logs-to-json {datamodel_logs_path} --output-path {output_path}"
        self.validate_wildcard_logs(
            command,
            datamodel_logs_path,
            expected_report_path,
            output_path,
            spec_version,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
