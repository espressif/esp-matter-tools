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

import json
import re
import logging
import os
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def get_id_name_lambda():
    """Get a lambda function that returns the id and name of an object"""
    return lambda x: (int(x.get_id(), 16), x.name)


def modify_id(id):
    """Modify the id to 0x prefixed hex value"""
    try:
        id_int = int(id, 0)
        return f"0x{id_int:04X}"
    except Exception as e:
        raise Exception(f"Error modifying id {id}: {str(e)}") from e


def clean_string(name):
    """Remove special characters from a string"""
    if name is None:
        return None
    name = re.sub(r"[^a-zA-Z0-9]", "", name)
    return name.lower()


def convert_to_snake_case(name):
    """Convert a name to snake_case"""
    if name is None:
        return None
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[\/_|\{\}\(\)\\-]", "_", name)
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-zA-Z])([0-9])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


def check_valid_id(id):
    """Check if an id is valid"""
    if id is None or id == "":
        return False
    elif not is_hex_value(id):
        return False
    if id in ["ID-TBD"]:
        return False
    return True


def safe_get_attr(obj, attr_name, default=None):
    """Safely get an attribute from an object, returning default if attribute doesn't exist"""
    return getattr(obj, attr_name, default) if obj else default


def hex_to_int(value):
    """Convert a hex string to an integer
    Args:
        value: The value to convert. can be a list, int or string
    Returns:
        The converted value. if list, returns a list of converted values. if int, returns the value. if string, returns the converted value.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return [hex_to_int(v) for v in value]
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    return value


def is_hex_value(value):
    """Check if a value is a valid hex value e.g. 0x0001"""
    try:
        if value.startswith("0x"):
            return True
        int(value, 16)
        return True
    except ValueError:
        return False


def load_json_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Load and parse a JSON file with error handling"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Error reading JSON file {file_path}: {str(e)}") from e


def write_to_json_file(file_path: str, data: Any) -> bool:
    """Write data to a JSON file"""
    try:
        parent_dir = os.path.dirname(file_path)
        os.makedirs(parent_dir, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, sort_keys=True)
        return True
    except Exception as e:
        raise Exception(f"Error writing to {file_path}: {str(e)}") from e
