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
import pytest

# Import the module under test
from dmv_tool.parsers.wildcard_logs import (
    parse_id_name_string,
    convert_value,
    convert_cluster_list_to_objects,
    parse_metadata_line,
    parse_block,
    parse_input,
    process_attribute_data,
    parse_datamodel_logs,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")


class TestParseIdNameString:
    """Test the parse_id_name_string function."""

    def test_decimal_id_format(self):
        """Test parsing decimal ID format."""
        result = parse_id_name_string("3 (identify)")
        assert result == {"id": "0x0003", "name": "identify"}

    def test_hex_id_only(self):
        """Test parsing hex ID without name."""
        result = parse_id_name_string("0x0003")
        assert result == "0x0003"

    def test_missing_name(self):
        """Test parsing when name is missing."""
        result = parse_id_name_string("0x0003")
        assert result == "0x0003"

    def test_empty_parentheses(self):
        """Test parsing with empty parentheses."""
        result = parse_id_name_string("3 ()")
        assert result == {"id": "0x0003", "name": ""}

    def test_whitespace_handling(self):
        """Test that whitespace is handled correctly."""
        result = parse_id_name_string("  3   (  identify  )  ")
        assert result == {"id": "0x0003", "name": "identify"}

    def test_special_characters_in_name(self):
        """Test names with special characters."""
        result = parse_id_name_string("3 (identify_time-value)")
        assert result == {"id": "0x0003", "name": "identify_time_value"}


class TestConvertValue:
    """Test the convert_value function."""

    def test_hex_value(self):
        """Test converting hex values."""
        assert convert_value("0x1234") == "0x1234"
        assert convert_value("0xABCD") == "0xABCD"

    def test_integer_value(self):
        """Test converting integer values."""
        assert convert_value("1234") == 1234
        assert convert_value("0") == 0

    def test_boolean_true(self):
        """Test converting boolean true values."""
        assert convert_value("true") is True
        assert convert_value("TRUE") is True
        assert convert_value("True") is True

    def test_boolean_false(self):
        """Test converting boolean false values."""
        assert convert_value("false") is False
        assert convert_value("FALSE") is False
        assert convert_value("False") is False

    def test_string_value(self):
        """Test converting string values."""
        assert convert_value("hello") == "hello"
        assert convert_value("") == ""

    def test_mixed_case_strings(self):
        """Test mixed case strings that aren't booleans."""
        assert convert_value("TrueValue") == "TrueValue"
        assert convert_value("FalseAlarm") == "FalseAlarm"


class TestConvertClusterListToObjects:
    """Test the convert_cluster_list_to_objects function."""

    def test_empty_list(self):
        """Test with empty cluster list."""
        result = convert_cluster_list_to_objects([])
        assert result == []

    def test_single_cluster(self):
        """Test with single cluster."""
        cluster_list = ["0x0003 (identify)"]
        result = convert_cluster_list_to_objects(cluster_list)
        expected = [{"id": "0x0003 (identify)"}]
        assert result == expected

    def test_multiple_clusters(self):
        """Test with multiple clusters."""
        cluster_list = ["0x0003 (identify)", "0x0004 (groups)", "0x0006 (on_off)"]
        result = convert_cluster_list_to_objects(cluster_list)
        expected = [
            {"id": "0x0003 (identify)"},
            {"id": "0x0004 (groups)"},
            {"id": "0x0006 (on_off)"},
        ]
        assert result == expected


class TestParseMetadataLine:
    """Test the parse_metadata_line function."""

    def test_valid_too_line(self):
        """Test parsing valid [TOO] metadata line."""
        line = "Endpoint: 1 Cluster: 0x0006 Attribute 0x0000 DataVersion: 123"
        result = parse_metadata_line(line)
        expected = {"Endpoint": 1, "Cluster": "0x0006", "Attribute": "0x0000"}
        assert result == expected

    def test_invalid_too_line(self):
        """Test parsing invalid metadata line."""
        line = "    device type: 0x0103 (door_lock)"
        result = parse_metadata_line(line)
        assert result == {}

    def test_empty_line(self):
        """Test parsing empty line."""
        line = ""
        result = parse_metadata_line(line)
        assert result == {}

    def test_malformed_too_line(self):
        """Test parsing malformed [TOO] line."""
        line = "Endpoint: invalid Cluster: 0x0006"
        result = parse_metadata_line(line)
        assert result == {}


class TestParseBlock:
    """Test the parse_block function."""

    def test_simple_key_value_parsing(self):
        """Test parsing simple key-value pairs."""
        lines = ["revision: 2", "feature_map: 0x0001"]
        result, next_index = parse_block(lines, 0)

        assert result["revision"] == 2
        assert result["feature_map"] == "0x0001"
        assert next_index == 2

    def test_empty_lines_handling(self):
        """Test parsing with empty lines."""
        lines = ["", "revision: 2", "", "feature_map: 0x0001"]
        result, next_index = parse_block(lines, 0)

        assert result["revision"] == 2
        assert result["feature_map"] == "0x0001"
        assert next_index == 4

    def test_invalid_input_handling(self):
        """Test parsing with invalid input."""
        lines = []
        result, next_index = parse_block(lines, 0)

        assert result == {}
        assert next_index == 0


class TestParseInput:
    """Test the parse_input function."""

    def test_parse_with_metadata_line(self):
        """Test parsing input with metadata line."""
        text = """Endpoint: 1 Cluster: 0x0006 Attribute 0x0000 DataVersion: 123
revision: 2
feature_map: 0x0001"""
        result = parse_input(text)

        assert result["Endpoint"] == 1
        assert result["Cluster"] == "0x0006"
        assert result["Attribute"] == "0x0000"
        assert result["revision"] == 2
        assert result["feature_map"] == "0x0001"

    def test_parse_empty_input(self):
        """Test parsing empty input."""
        result = parse_input("")
        assert result == {}

    def test_parse_simple_key_values(self):
        """Test parsing simple key-value pairs without metadata."""
        text = """revision: 2
feature_map: 0x0001
enabled: true"""
        result = parse_input(text)

        # First line is treated as metadata (and fails to parse), so only the last processed line is kept
        assert result["enabled"] is True


class TestProcessAttributeData:
    """Test the process_attribute_data function."""

    def test_process_valid_attributes(self):
        """Test processing valid attribute data."""
        attribute_lines = [
            """Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_FFFB DataVersion: 648768717
AttributeList: 8 entries
     [1]: 0 (WindowStatus)
     [2]: 1 (AdminFabricIndex)
     [3]: 2 (AdminVendorId)
     [4]: 65533 (ClusterRevision)
     [5]: 65532 (FeatureMap)
     [6]: 65531 (AttributeList)
     [7]: 65529 (AcceptedCommandList)
     [8]: 65528 (GeneratedCommandList)"""
        ]
        endpoints = {}

        process_attribute_data(attribute_lines, endpoints)

        str_cluster_id = "0x003C"
        ep_parsed_data = endpoints[0][str_cluster_id][0]
        assert ep_parsed_data.get("Endpoint") == 0
        assert ep_parsed_data.get("Cluster") == "0x0000_003C"
        assert ep_parsed_data.get("Attribute") == "0x0000_FFFB"

        attribute_list = ep_parsed_data.get("AttributeList")
        assert len(attribute_list) == 8
        assert attribute_list[0].get("id") == "0x0000"
        assert attribute_list[0].get("name") == "window_status"


class TestParseDatamodelLogs:
    """Test the parse_datamodel_logs function."""

    def test_parse_sample_data(self):
        sample_data = """
        [0;32m[1756719618.222] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_0000 DataVersion: 648768717[0m
[0;32m[1756719618.222] [51774:5149697:chip] [TOO]   WindowStatus: 0[0m
[0;32m[1756719618.222] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_0001 DataVersion: 648768717[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO]   AdminFabricIndex: null[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_0002 DataVersion: 648768717[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO]   AdminVendorId: null[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_FFFD DataVersion: 648768717[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO]   ClusterRevision: 1[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_FFFC DataVersion: 648768717[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO]   FeatureMap: 0[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO] Endpoint: 0 Cluster: 0x0000_003C Attribute 0x0000_FFFB DataVersion: 648768717[0m
[0;32m[1756719618.223] [51774:5149697:chip] [TOO]   AttributeList: 8 entries[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [1]: 0 (WindowStatus)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [2]: 1 (AdminFabricIndex)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [3]: 2 (AdminVendorId)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [4]: 65533 (ClusterRevision)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [5]: 65532 (FeatureMap)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [6]: 65531 (AttributeList)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [7]: 65529 (AcceptedCommandList)[0m
[0;32m[1756719618.224] [51774:5149697:chip] [TOO]     [8]: 65528 (GeneratedCommandList)[0m
"""
        expected_result = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {
                        "0x003C": {
                            "attributes": {
                                "0x0000": {"WindowStatus": 0},
                                "0x0001": {"AdminFabricIndex": None},
                                "0x0002": {"AdminVendorId": None},
                                "AttributeList": {
                                    "AttributeList": [
                                        {"id": "0x0000", "name": "window_status"},
                                        {"id": "0x0001", "name": "admin_fabric_index"},
                                        {"id": "0x0002", "name": "admin_vendor_id"},
                                        {"id": "0xFFFD", "name": "cluster_revision"},
                                        {"id": "0xFFFC", "name": "feature_map"},
                                        {"id": "0xFFFB", "name": "attribute_list"},
                                        {
                                            "id": "0xFFF9",
                                            "name": "accepted_command_list",
                                        },
                                        {
                                            "id": "0xFFF8",
                                            "name": "generated_command_list",
                                        },
                                    ]
                                },
                            },
                            "events": {},
                            "commands": {},
                            "features": {"FeatureMap": {"FeatureMap": 0}},
                            "revisions": {
                                "ClusterRevision": {"ClusterRevision": 1},
                            },
                        }
                    },
                }
            ]
        }

        result = parse_datamodel_logs(sample_data)

        assert "endpoints" in result
        assert isinstance(result["endpoints"], list)
        assert len(result["endpoints"]) > 0
        ep_data = result["endpoints"][0]
        assert ep_data.get("id") == 0
        assert result == expected_result

    def test_parse_empty_data(self):
        """Test parsing empty data raises appropriate error."""
        with pytest.raises(ValueError, match="No \\[TOO\\] entries found"):
            parse_datamodel_logs("")

    def test_parse_invalid_data(self):
        """Test parsing malformed data raises appropriate error."""
        invalid_data = "this is not valid log data"
        with pytest.raises(ValueError, match="No \\[TOO\\] entries found"):
            parse_datamodel_logs(invalid_data)


if __name__ == "__main__":
    pytest.main([__file__])
