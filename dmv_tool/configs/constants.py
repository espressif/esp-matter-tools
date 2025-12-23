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

# Supported Matter specification versions
SUPPORTED_SPEC_VERSIONS = [
    "1.2", "1.3", "1.4", "1.4.1", "1.4.2", "1.5"
]

# C++ reserved words to avoid using cluster or feature names
CPP_RESERVED_WORDS = ["auto", "switch"]

DEFAULT_OUTPUT_DIR = "out"
DEFAULT_PARSED_DATA_FILE = "parsed_data.json"
DEFAULT_REPORT_FILE = "report.txt"
