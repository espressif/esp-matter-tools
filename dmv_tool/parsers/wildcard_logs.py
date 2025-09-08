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
import logging
import os
import re

from .constants import GLOBAL_ATTRIBUTES
from dmv_tool.utils.helpers import (
    convert_to_snake_case,
    convert_to_hex,
)

logger = logging.getLogger(__name__)


def clean_line(line):
    """Remove terminal escape sequences and clean line

    Args:
        line: The line to clean
    Returns:
        The cleaned line

    """
    return re.sub(r"\x1b\[0m|ESC\[0m|\u241b\[0m", "", line).strip()


def parse_id_name_string(val):
    """Parse strings like '0 (Off)' to extract ID and name.

    Args:
        val: String value to parse

    Returns:
        Dict with id/name or formatted hex string
    """
    try:
        if not val:
            return val

        val = clean_line(val)

        pattern = r"^(\d+)\s*\((.*?)\)$"
        match = re.match(pattern, val)
        if match:
            id_num = int(match.group(1))
            name = match.group(2).strip()
            return {"id": f"0x{id_num:04X}", "name": convert_to_snake_case(name)}

        pattern2 = r"^(\d+)\s*\((.*?)\)"
        match2 = re.match(pattern2, val)
        if match2:
            id_num = int(match2.group(1))
            name = match2.group(2).strip()
            return {"id": f"0x{id_num:04X}", "name": convert_to_snake_case(name)}

        if val.startswith("0x"):
            hex_part = val.replace("0x", "").replace("_", "")
            id_num = int(hex_part, 16)
            return f"0x{id_num:04X}"

        if val.isdigit():
            id_num = int(val)
            return f"0x{id_num:04X}"

        return val

    except Exception as e:
        raise Exception(f"Unexpected error parsing ID/name string '{val}': {e}") from e


def convert_value(val):
    """Convert string values to appropriate types with parsing-specific logic.

    Args:
        val: Value to convert

    Returns:
        Converted value
    """
    try:
        if val is None:
            return None

        if not isinstance(val, str):
            return val

        val = clean_line(val)
        if not val:
            return val

        val_lower = val.lower()
        if val_lower == "null":
            return None
        if val_lower == "true":
            return True
        if val_lower == "false":
            return False

        if val.isdigit():
            num_val = int(val)
            if num_val > 2**32:
                logger.warning(
                    f"Large integer value detected: {num_val}, keeping as string"
                )
                return val
            return num_val

        parsed = parse_id_name_string(val)
        if isinstance(parsed, dict) and "id" in parsed and "name" in parsed:
            return parsed

        return val

    except Exception as e:
        raise Exception(f"Unexpected error converting value '{val}': {e}") from e


def convert_device_type_to_hex(obj):
    """Recursively convert DeviceType values to hex format with error handling.

    Args:
        obj: Object to process (can be dict, list, or any other type)
    Returns:
        Processed object with DeviceType values converted to hex

    """
    try:
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key == "DeviceType" and isinstance(value, int):
                    if 0 <= value <= 0xFFFF:
                        result[key] = f"0x{value:04X}"
                    else:
                        logger.warning(
                            f"DeviceType value {value} out of valid range (0-65535)"
                        )
                        result[key] = value
                else:
                    result[key] = convert_device_type_to_hex(value)
            return result
        elif isinstance(obj, list):
            result = []
            for i, item in enumerate(obj):
                result.append(convert_device_type_to_hex(item))
            return result
        else:
            return obj
    except Exception as e:
        raise Exception(f"Error in convert_device_type_to_hex: {e}") from e


def convert_cluster_list_to_objects(cluster_list):
    """Convert a list of cluster IDs to objects with id fields.

    Args:
        cluster_list: List of cluster IDs or objects

    Returns:
        List of cluster objects with id fields
    """
    if not isinstance(cluster_list, list):
        return cluster_list

    result = []
    for item in cluster_list:
        if isinstance(item, dict):
            result.append(item)
        elif isinstance(item, int):
            hex_id = f"0x{item:04X}"
            result.append({"id": hex_id})
        elif isinstance(item, str):
            if item.isdigit():
                int_val = int(item)
                hex_id = f"0x{int_val:04X}"
                result.append({"id": hex_id})
            else:
                result.append({"id": item})
        else:
            result.append(item)

    return result


def parse_metadata_line(line):
    """Parse metadata line to extract endpoint, cluster, and attribute info.

    Args:
        line: Line containing metadata information

    Returns:
        Parsed metadata dictionary
    """
    pattern = r"Endpoint:\s*(\d+)\s+Cluster:\s*(0x[\dA-Fa-f_]+)\s+Attribute\s*(0x[\dA-Fa-f_]+)\s+DataVersion:\s*(\d+)"
    match = re.match(pattern, line.strip())
    if match:
        return {
            "Endpoint": int(match.group(1)),
            "Cluster": match.group(2),
            "Attribute": match.group(3),
        }
    return {}


def parse_block(lines, index=0):
    """Parse a block of structured text into a dictionary.

    Args:
        lines: List of text lines to parse
        index: Starting index in the lines list

    Returns:
        Tuple of (parsed_dict, next_index)
    """
    result = {}

    try:
        if not lines or not isinstance(lines, list):
            logger.warning("Invalid lines input for parse_block")
            return result, index

        lines_len = len(lines)
        if index >= lines_len:
            return result, index

        list_pattern = re.compile(r"(\w+):\s+\d+\s+entries")
        item_pattern = re.compile(r"\[\d+\]:\s*\{?")
        value_pattern = re.compile(r"\[\d+\]:\s*(.+)")
        inline_obj_pattern = re.compile(r"(\w+):\s*\{")
        kv_pattern = re.compile(r"(\w+):\s*(.*)")

        while index < lines_len:
            line = clean_line(lines[index])
            if not line:
                index += 1
                continue

            m_list = list_pattern.match(line)
            if m_list:
                key = m_list.group(1)
                index += 1
                items = []
                while index < lines_len:
                    sub_line = clean_line(lines[index])
                    if item_pattern.match(sub_line):
                        if "{" in sub_line:
                            index += 1
                            item, index = parse_block(lines, index)
                            items.append(item)
                        else:
                            val_match = value_pattern.match(sub_line)
                            if val_match:
                                items.append(convert_value(val_match.group(1)))
                            index += 1
                    else:
                        break
                result[key] = items
                continue

            if line == "}":
                return result, index + 1

            m_inline_obj = inline_obj_pattern.match(line)
            if m_inline_obj:
                key = m_inline_obj.group(1)
                index += 1
                nested_obj, index = parse_block(lines, index)
                result[key] = nested_obj
                continue

            kv_match = kv_pattern.match(line)
            if kv_match:
                key, val = kv_match.groups()
                val = val.strip()
                if val != "":
                    result[key] = convert_value(val)
                index += 1
            else:
                index += 1

        return result, index

    except Exception as e:
        raise Exception(f"Critical error in parse_block: {e}") from e


def parse_input(text):
    """Parse input text containing metadata and structured data.

    Args:
        text: Input text to parse

    Returns:
        Parsed data dictionary
    """
    lines = text.strip().splitlines()
    top_level = {}

    if lines:
        metadata_line = clean_line(lines[0])
        top_level = parse_metadata_line(metadata_line)
        lines = lines[1:]

    parsed_body, _ = parse_block(lines)
    top_level.update(parsed_body)
    return top_level


def process_attribute_data(attribute_lines, endpoints):
    """Process a single attribute's data and add it to the endpoints structure.

    Args:
        attribute_lines: List of lines containing attribute data
        endpoints: Endpoints dictionary to update
    """
    if not attribute_lines:
        return

    try:
        input_str = "\n".join(attribute_lines)
        parsed = parse_input(input_str)

        endpoint_id = parsed.get("Endpoint", "unknown")
        cluster_id = parsed.get("Cluster", "unknown")

        if endpoint_id == "unknown":
            logger.error("Endpoint ID is unknown")
            return

        if cluster_id == "unknown":
            logger.error("Cluster ID is unknown")
            return

        cluster_id = parse_id_name_string(cluster_id)
        if not isinstance(cluster_id, str):
            cluster_id = str(cluster_id)

        if endpoint_id not in endpoints:
            endpoints[endpoint_id] = {}
        if cluster_id not in endpoints[endpoint_id]:
            endpoints[endpoint_id][cluster_id] = []

        endpoints[endpoint_id][cluster_id].append(parsed)

    except Exception as e:
        raise Exception(f"Error processing attribute data: {e}") from e


def parse_datamodel_logs(data):
    """Parse the complete datamodel logs and organize by endpoint and cluster.

    Args:
        data: Raw log data containing [TOO] entries

    Returns:
        Structured data organized by endpoints and clusters
    """
    logger.debug("Starting datamodel parsing...")
    endpoints = {}

    lines = data.split("\n")
    too_lines = [line for line in lines if "[TOO]" in line]
    logger.debug(f"Found {len(too_lines)} [TOO] entries to process")

    if len(too_lines) == 0:
        raise ValueError(
            "No [TOO] entries found in the file. This appears to be a different type of log file that is not compatible with this parser."
        )

    endpoint_attribute_data = []

    try:
        for line in too_lines:
            info = line.split("[TOO]", 1)[-1]
            if "Endpoint" in info:
                if endpoint_attribute_data:
                    process_attribute_data(endpoint_attribute_data, endpoints)
                endpoint_attribute_data = [f"{info}"]
            else:
                if endpoint_attribute_data:
                    endpoint_attribute_data.append(f"{info}")

        if endpoint_attribute_data:
            process_attribute_data(endpoint_attribute_data, endpoints)

        logger.debug("Converting to final format...")
        result = {"endpoints": []}

        exclude_keys = {"Endpoint", "Cluster", "Attribute"}

        for endpoint_id in sorted(endpoints.keys()):
            endpoint_data = {"id": endpoint_id, "clusters": {}}

            for cluster_id in sorted(endpoints[endpoint_id].keys()):
                hex_cluster_id = convert_to_hex(cluster_id)
                logger.debug(
                    f"Processing cluster {hex_cluster_id} on endpoint {endpoint_id}"
                )

                cluster_data = {
                    "attributes": {},
                    "events": {},
                    "commands": {},
                    "features": {},
                    "revisions": {},
                }

                for attr_data in endpoints[endpoint_id][cluster_id]:
                    attr_id = attr_data.get("Attribute", "unknown")
                    if attr_id == "unknown":
                        logger.error(
                            f"Attribute ID is unknown for cluster {cluster_id} on endpoint {endpoint_id}"
                        )
                        continue

                    attr_id = parse_id_name_string(attr_id)
                    if not isinstance(attr_id, str):
                        attr_id = str(attr_id)

                    clean_attr_data = {
                        k: v for k, v in attr_data.items() if k not in exclude_keys
                    }

                    for key, value in clean_attr_data.items():
                        if key in ["ServerList", "ClientList"] and isinstance(
                            value, list
                        ):
                            clean_attr_data[key] = convert_cluster_list_to_objects(
                                value
                            )
                        elif key == "DeviceTypeList" and isinstance(value, list):
                            formatted_device_types = []
                            for device_type in value:
                                if isinstance(device_type, dict):
                                    device_type_obj = device_type.copy()
                                    if "DeviceType" in device_type_obj:
                                        dt_val = device_type_obj["DeviceType"]
                                        if isinstance(dt_val, int):
                                            device_type_obj["DeviceType"] = (
                                                f"0x{dt_val:04X}"
                                            )
                                    formatted_device_types.append(device_type_obj)
                                else:
                                    formatted_device_types.append(device_type)
                            clean_attr_data[key] = formatted_device_types

                    if attr_id in GLOBAL_ATTRIBUTES:
                        category, attr_name = GLOBAL_ATTRIBUTES[attr_id]
                        cluster_data[category][attr_name] = clean_attr_data
                    else:
                        cluster_data["attributes"][attr_id] = clean_attr_data

                if any(cluster_data.values()):
                    endpoint_data["clusters"][hex_cluster_id] = cluster_data

            result["endpoints"].append(endpoint_data)

        result = convert_device_type_to_hex(result)

        return result

    except Exception as e:
        raise ValueError(f"Error during parsing: {str(e)}") from e


def parse_wildcard_file(file_path, output_path):
    """Parse chip-tool wildcard logs and extract structured device data.

    Args:
        file_path: Path to the chip-tool wildcard log file to parse
        output_path: Output path for parsed JSON data
    """
    try:
        logger.info(f"Reading wildcard log file: {file_path}")
        with open(file_path, "r") as file:
            data = file.read()

        logger.info("Parsing wildcard log data...")
        parsed_data = parse_datamodel_logs(data)

        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        logger.info(f"Writing parsed data to: {output_path}")
        with open(output_path, "w") as file:
            json.dump(parsed_data, file, indent=2)

        endpoints = parsed_data.get("endpoints", [])
        total_clusters = sum(len(ep.get("clusters", {})) for ep in endpoints)

        logger.info(
            f"Found {len(endpoints)} endpoints with {total_clusters} total clusters"
        )
        logger.info(f"Parsed data saved to: {output_path}")

    except Exception as e:
        raise ValueError(f"Parse error: {str(e)}") from e
