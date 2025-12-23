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

logger = logging.getLogger(__name__)


def extract_id_from_element(element):
    """Extract ID from element in various formats (dict, int, str).

    Args:
        element: Element that can be dict with 'id' key, integer, or string
    Returns:
        Standardized hex ID string or None if invalid

    """
    try:
        if isinstance(element, dict):
            return element.get("id")
        elif isinstance(element, int):
            return f"0x{element:04X}"
        elif isinstance(element, str):
            return element
        else:
            return None
    except Exception as e:
        raise Exception(f"Error extracting ID from element {element}: {e}") from e


def get_nested_list(data, *path_keys):
    """Safely extract nested list from data structure.

    Args:
        data: The data structure to navigate
        path_keys: Variable number of keys to navigate through
    Returns:
        The nested list or empty list if not found

    Examples:
        get_nested_list(cluster, "attributes", "AttributeList", "AttributeList")
        get_nested_list(cluster, "commands", "GeneratedCommandList", "GeneratedCommandList")

    """
    try:
        current = data
        for key in path_keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return []

        return current if isinstance(current, list) else []
    except Exception as e:
        raise Exception(
            f"Error extracting nested list with path {path_keys}: {e}"
        ) from e


def find_element_in_list(element_list, target_id):
    """Find if target_id exists in a list of elements with various formats.

    Args:
        element_list: List of elements (dict/int/str format)
        target_id: Target ID to search for
    Returns:
        True if found, False otherwise

    """
    if not isinstance(element_list, list):
        if element_list is not None:
            logger.debug(f"Expected list for element search, got {type(element_list)}")
        return False

    if not target_id:
        logger.debug("Empty target_id provided for element search")
        return False

    try:
        for i, element in enumerate(element_list):
            element_id = extract_id_from_element(element)
            if element_id == target_id:
                return True
        return False
    except Exception as e:
        raise Exception(f"Error searching for {target_id} in element list: {e}") from e


def process_element_list(element_list, exclude_ids=None):
    """Process a list of elements and return their IDs, optionally excluding certain IDs.

    Args:
        element_list: List of elements to process
        exclude_ids: Set or list of IDs to exclude (Default value = None)
    Returns:
        List of extracted IDs

    """
    if not isinstance(element_list, list):
        return []

    exclude_set = set(exclude_ids) if exclude_ids else set()
    result = []

    try:
        for element in element_list:
            element_id = extract_id_from_element(element)
            if element_id and element_id not in exclude_set:
                result.append(element_id)
        return result
    except Exception as e:
        raise Exception(f"Error processing element list: {e}") from e


def find_duplicates_in_element_list(element_list):
    """Find duplicate elements in a list by their IDs.

    Args:
        element_list: List of elements to check for duplicates
    Returns:
        List of duplicate element info with id, name, and count

    """
    if not isinstance(element_list, list):
        return []

    id_counts = {}
    id_to_element = {}

    try:
        for element in element_list:
            element_id = extract_id_from_element(element)
            if element_id:
                if element_id not in id_counts:
                    id_counts[element_id] = 0
                    id_to_element[element_id] = element
                id_counts[element_id] += 1

        duplicates = []
        for element_id, count in id_counts.items():
            if count > 1:
                element = id_to_element[element_id]
                element_name = "Unknown"
                if isinstance(element, dict):
                    element_name = element.get("name", "Unknown")
                duplicates.append(
                    {
                        "id": element_id,
                        "name": element_name,
                        "count": count,
                    }
                )

        return duplicates
    except Exception as e:
        raise Exception(f"Error finding duplicates in element list: {e}") from e


def convert_specification_version(spec_version):
    """Convert SpecificationVersion numeric value to version string.

    Args:
        spec_version: Numeric SpecificationVersion value
    Returns:
        Version string if supported, None otherwise
    """
    try:
        logger.debug(
            f"Converting SpecificationVersion {spec_version} to version string"
        )
        hex_version = f"{spec_version:08X}"

        major = int(hex_version[0:2], 16)
        minor = int(hex_version[2:4], 16)
        patch = int(hex_version[4:6], 16)
        build = int(hex_version[6:8], 16)

        logger.debug(
            f"SpecificationVersion {spec_version} -> hex {hex_version} -> {major}.{minor}.{patch}.{build}"
        )

        if major == 1:
            if minor == 2:
                version = "1.2"
            elif minor == 3:
                version = "1.3"
            elif minor == 4:
                if patch == 0:
                    version = "1.4"
                elif patch == 1:
                    version = "1.4.1"
                elif patch > 1:
                    version = "1.4.2"
                else:
                    version = "1.4"  # Default to 1.4 for unknown patch
            elif minor == 5:
                version = "1.5"
            elif minor == 6:
                version = "1.6"
            elif minor == 7:
                version = "1.7"
            elif minor == 8:
                version = "1.8"
            else:
                logger.debug(
                    f"SpecificationVersion {spec_version} not in supported minor versions list, defaulting to 1.5"
                )
                return "1.5"  # Future versions default to 1.5
        else:
            logger.debug(
                f"SpecificationVersion {spec_version} not in supported major versions list, defaulting to 1.5"
            )
            return "1.5"  # Future versions default to 1.5

        return version

    except Exception as e:
        raise Exception(
            f"Error converting SpecificationVersion {spec_version}: {e}"
        ) from e
