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
ESP Matter Data Model Validation (DMV) Tool

A Python package for validating Matter device data model conformance
against the official Matter specification.
"""

# Public API exports
from .validators.conformance_checker import (
    validate_device_conformance,
    detect_spec_version_from_parsed_data,
)
from .parsers.wildcard_logs import parse_datamodel_logs
from .generators.main import generate_chip_validation_data

__all__ = [
    "validate_device_conformance",
    "detect_spec_version_from_parsed_data",
    "parse_datamodel_logs",
    "generate_chip_validation_data",
]

