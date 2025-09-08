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

import subprocess
import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration for individual test case
    Test case json is converted into this class object for easier access and validation
    This class object is then used to run the test case and validate the output

    Args:
        description: Description of the test case
        command: Command to run the test case
        expected_output: Expected output of the test case
        validate_cert: Whether to validate the certificates generated from the test case output
        validate_path: Whether to validate the output paths generated from the test case output
        validate_no_bin: Whether to validate that no binary partition files are generated from the test case output
    """

    description: str
    command: str
    expected_output: str
    validate_cert: bool = False
    validate_cn_in_path: bool = False
    validate_cn_not_in_path: bool = False
    validate_no_bin: bool = False
    validate_csv_quoting: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """
        Convert test case json into Config class object
        This is used to run the test case and validate the output
        This is class method to allow for easy conversion from json to Config class object

        Args:
            data: Test case json

        Returns:
            Config: Config class object
        """
        return cls(
            description=data.get("description", ""),
            command=data.get("command", ""),
            expected_output=data.get("expected_output", ""),
            validate_cert=data.get("validate_cert", False),
            validate_cn_in_path=data.get("validate_cn_in_path", False),
            validate_cn_not_in_path=data.get("validate_cn_not_in_path", False),
            validate_no_bin=data.get("validate_no_bin", False),
            validate_csv_quoting=data.get("validate_csv_quoting", False),
        )


@dataclass
class ParsedOutput:
    """Parsed output of the esp-matter-mfg-tool command"""

    out_path: str = ""
    dac_cert: str = ""
    pai_cert: str = ""


def run_command(command):
    """Run a command and capture output"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return result
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out: {e}")
        return e


def parse_mfg_tool_output(output: str) -> List[ParsedOutput]:
    """Parse the output of the esp-matter-mfg-tool command"""
    parsed_output = []

    for line in output.split("\n"):
        if "Generated output files at:" in line:
            out_path = line.split("Generated output files at: ")[1].strip()
            parsed_output.append(
                ParsedOutput(
                    out_path=out_path,
                    dac_cert=f"{out_path}/internal/DAC_cert.der",
                    pai_cert=f"{out_path}/internal/PAI_cert.der",
                )
            )

    return parsed_output
