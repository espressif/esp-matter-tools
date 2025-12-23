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
import re

logger = logging.getLogger(__name__)


def convert_to_snake_case(name):
    """Convert a name to snake_case.

    Example: PM2.5 Concentration Measurement -> pm2_5_concentration_measurement

    Args:
        name: The name to convert to snake_case
    Returns:
        The converted name

    """
    if name is None:
        return None
    if name.endswith("Command"):
        name = name[:-7].replace(" ", "_")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[\/_|\{\}\(\)\\-]", "_", name)
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-zA-Z])([0-9])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


def convert_to_hex(value):
    """Convert value to hex ID format consistently

    Args:
        value: The value to convert
    Returns:
        The converted value

    """
    try:
        if isinstance(value, int):
            return f"0x{value:04X}"
        elif isinstance(value, str):
            if value.startswith("0x"):
                return value
            elif value.isdigit():
                return f"0x{int(value):04X}"
            else:
                return value
        else:
            return value
    except Exception as e:
        logger.error(f"Error converting value to hex ID: {e}")
        return value


def convert_to_int(value):
    """Convert value to integer.
    Args:
        value: The value to convert
    Returns:
        The converted value
    """
    try:
        if not value:
            return None
        return int(str(value), 0)
    except Exception as e:
        logger.error(f"Error converting value to integer: {e}")
        return None
