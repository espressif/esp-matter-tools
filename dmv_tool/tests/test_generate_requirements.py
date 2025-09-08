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
from unittest.mock import Mock, patch

from dmv_tool.generators.main import generate_chip_validation_data
from dmv_tool.generators.core import (
    create_cluster_lookup,
    convert_feature_name_to_code,
    merge_device_cluster_with_full_definition,
    combine_clusters_and_devices_json,
    combine_clusters_devices_json,
)
from dmv_tool.generators.xml_parser import (
    get_base_and_derived_cluster_files,
    process_cluster_files,
    process_device_files,
    generate_json,
)

logger = logging.getLogger(__name__)


class TestGenerateRequirements:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.chip_path = os.path.join(self.temp_dir, "chip")
        self.output_dir = os.path.join(self.temp_dir, "output")
        self.spec_version_dir = "1.4.2"
        os.makedirs(self.chip_path, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(
            os.path.join(self.chip_path, f"data_model/{self.spec_version_dir}"),
            exist_ok=True,
        )

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch("dmv_tool.generators.main.generate_json")
    @patch("dmv_tool.generators.main.combine_clusters_devices_json")
    def test_generate_datamodel_requirement_success(
        self, mock_combine, mock_generate_json
    ):
        generate_chip_validation_data(
            self.chip_path, self.spec_version_dir, self.output_dir
        )
        mock_generate_json.assert_called_once()
        mock_combine.assert_called_once()
        call_args = mock_combine.call_args[0]
        assert call_args[0].endswith("clusters.json")
        assert call_args[1].endswith("device_types.json")
        assert call_args[2].endswith(f"validation_data_{self.spec_version_dir}.json")


class TestRequirementsBuilder:
    def setup_method(self):
        self.output_dir = tempfile.mkdtemp()
        os.makedirs(self.output_dir, exist_ok=True)

    def teardown_method(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_create_cluster_lookup(self):
        clusters = [
            {"id": "0x0001", "name": "cluster1"},
            {"id": "0x0002", "name": "cluster2"},
            {"name": "cluster3"},
        ]
        result = create_cluster_lookup(clusters)
        assert len(result) == 2
        assert "0x0001" in result
        assert "0x0002" in result
        assert result["0x0001"]["name"] == "cluster1"
        assert result["0x0002"]["name"] == "cluster2"

    def test_convert_feature_name_to_code(self):
        cluster_features = [
            {"name": "lighting", "code": "LT"},
            {"name": "color_control", "code": "CC"},
            {"code": "AC"},
        ]
        assert convert_feature_name_to_code("lighting", cluster_features) == "LT"
        assert convert_feature_name_to_code("color_control", cluster_features) == "CC"
        assert convert_feature_name_to_code("AC", cluster_features) == "AC"
        assert convert_feature_name_to_code("unknown", cluster_features) == "unknown"

    def test_merge_device_cluster_with_full_definition(self):
        device_cluster = {
            "id": "0x0001",
            "type": "server",
            "required": True,
            "features": [
                {"name": "lighting", "is_mandatory": True},
                {"name": "color_control", "is_mandatory": True},
            ],
            "commands": [],
            "attributes": [],
        }
        full_cluster = {
            "id": "0x0001",
            "name": "OnOff",
            "features": [
                {
                    "id": "0x0001",
                    "name": "lighting",
                    "code": "LT",
                    "required": "False",
                    "attributes": [{"id": "0x0004", "name": "on_level"}],
                },
                {
                    "id": "0x0002",
                    "name": "color_control",
                    "code": "CC",
                    "required": "False",
                    "attributes": [{"id": "0x0005", "name": "color_temperature"}],
                },
                {
                    "id": "0x0003",
                    "name": "temperature_control",
                    "code": "TC",
                    "required": "False",
                    "attributes": [{"id": "0x0006", "name": "current_level"}],
                },
            ],
            "commands": [
                {"id": "0x0001", "name": "on", "mandatory": True},
                {"id": "0x0002", "name": "off", "mandatory": True},
                {"id": "0x0003", "name": "toggle", "mandatory": False},
            ],
            "attributes": [
                {"id": "0x0001", "name": "on_off", "mandatory": True},
                {"id": "0x0002", "name": "global_scene_control", "mandatory": False},
            ],
        }

        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        result = merge_device_cluster_with_full_definition(
            device_cluster,
            full_cluster,
            validation_data_json_file,
            self.output_dir,
        )
        assert result["type"] == "server"
        assert result["required"] is True
        assert len(result["features"]) == 3
        assert result["features"][0]["required"] is True
        assert result["features"][1]["required"] is True
        assert result["features"][2]["required"] is False
        assert len(result["commands"]) == 2
        assert len(result["attributes"]) == 1

    def test_merge_device_cluster_no_device_features(self):
        device_cluster = {"id": "0x0001", "type": "client", "required": False}
        full_cluster = {
            "id": "0x0001",
            "name": "OnOff",
            "features": [{"id": "0x0001", "name": "lighting", "code": "LT"}],
            "commands": [{"id": "0x0001", "name": "On", "mandatory": True}],
            "attributes": [{"id": "0x0001", "name": "OnOff", "mandatory": True}],
        }

        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        result = merge_device_cluster_with_full_definition(
            device_cluster,
            full_cluster,
            validation_data_json_file,
            self.output_dir,
        )
        assert result["type"] == "client"
        assert result["required"] is False
        assert len(result["features"]) == 1
        assert len(result["commands"]) == 1
        assert len(result["attributes"]) == 1

    @patch("dmv_tool.generators.core.load_json_file")
    def test_combine_clusters_and_devices_json_success(self, mock_load_json):
        clusters_data = [
            {
                "id": "0x0001",
                "name": "OnOff",
                "features": [{"id": "0x0001", "name": "lighting", "code": "LT"}],
                "commands": [{"id": "0x0001", "name": "On"}],
                "attributes": [{"id": "0x0001", "name": "OnOff"}],
            }
        ]
        devices_data = [
            {
                "id": "0x0001",
                "name": "Light",
                "clusters": [
                    {
                        "id": "0x0001",
                        "type": "server",
                        "required": True,
                        "features": [{"name": "lighting", "is_mandatory": True}],
                    }
                ],
            }
        ]
        mock_load_json.side_effect = [clusters_data, devices_data]
        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        result = combine_clusters_and_devices_json(
            "clusters.json",
            "devices.json",
            validation_data_json_file,
            self.output_dir,
        )
        assert len(result) == 1
        assert result[0]["name"] == "Light"
        assert len(result[0]["clusters"]) == 1
        assert result[0]["clusters"][0]["type"] == "server"
        assert result[0]["clusters"][0]["required"] is True

    @patch("dmv_tool.generators.core.load_json_file")
    def test_combine_clusters_and_devices_json_missing_cluster(self, mock_load_json):
        clusters_data = [{"id": "0x0002", "name": "DifferentCluster"}]
        devices_data = [
            {
                "id": "0x0001",
                "name": "Light",
                "clusters": [{"id": "0x0001", "type": "server", "required": True}],
            }
        ]
        mock_load_json.side_effect = [clusters_data, devices_data]
        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        result = combine_clusters_and_devices_json(
            "clusters.json",
            "devices.json",
            validation_data_json_file,
            self.output_dir,
        )
        assert len(result) == 1
        assert result[0]["name"] == "Light"
        assert len(result[0]["clusters"]) == 1
        assert result[0]["clusters"][0]["type"] == "server"

    @patch("dmv_tool.generators.core.load_json_file")
    def test_combine_clusters_and_devices_json_load_failure(self, mock_load_json):
        mock_load_json.return_value = None
        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        result = combine_clusters_and_devices_json(
            "clusters.json",
            "devices.json",
            validation_data_json_file,
            self.output_dir,
        )
        assert result == {}

    @patch("dmv_tool.generators.core.combine_clusters_and_devices_json")
    @patch("dmv_tool.generators.core.write_to_json_file")
    def test_combine_clusters_devices_json_success(self, mock_write, mock_combine):
        mock_combine.return_value = [{"id": "0x0001", "name": "Light"}]
        mock_write.return_value = True
        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        combine_clusters_devices_json(
            "clusters.json",
            "devices.json",
            validation_data_json_file,
            self.output_dir,
        )
        mock_combine.assert_called_once_with(
            "clusters.json",
            "devices.json",
            validation_data_json_file,
            self.output_dir,
        )
        mock_write.assert_called_once_with(
            validation_data_json_file, [{"id": "0x0001", "name": "Light"}]
        )

    def test_combine_clusters_devices_json_combine_failure(self):
        validation_data_json_file = os.path.join(
            self.output_dir, "validation_data.json"
        )
        cluster_file = os.path.join(self.output_dir, "clusters.json")
        with open(cluster_file, "w") as f:
            f.write("{}")
        device_file = os.path.join(self.output_dir, "device_types.json")
        with open(device_file, "w") as f:
            f.write("{}")
        with pytest.raises(Exception, match="Failed to combine data"):
            combine_clusters_devices_json(
                cluster_file,
                device_file,
                validation_data_json_file,
                self.output_dir,
            )


class TestChipXmlParser:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_get_base_and_derived_cluster_files_empty_dir(self):
        base_files, derived_files = get_base_and_derived_cluster_files(self.temp_dir)
        assert base_files == []
        assert derived_files == []

    def test_get_base_and_derived_cluster_files_with_xml(self):
        base_xml = """<?xml version="1.0"?> \
        <cluster xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                 xsi:schemaLocation="types types.xsd cluster cluster.xsd" \
                 id="0x0006" name="OnOff" revision="4">
            <classification hierarchy="base" role="application"/>
        </cluster>"""
        derived_xml = """<?xml version="1.0"?> \
        <cluster xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
                 xsi:schemaLocation="types types.xsd cluster cluster.xsd" \
                 id="0x0007" name="DerivedOnOff" revision="1">
            <classification hierarchy="derived" role="application" baseCluster="OnOff"/>
        </cluster>"""
        base_file = os.path.join(self.temp_dir, "base.xml")
        derived_file = os.path.join(self.temp_dir, "derived.xml")
        non_xml_file = os.path.join(self.temp_dir, "readme.txt")
        with open(base_file, "w") as f:
            f.write(base_xml)
        with open(derived_file, "w") as f:
            f.write(derived_xml)
        with open(non_xml_file, "w") as f:
            f.write("Not XML")
        base_files, derived_files = get_base_and_derived_cluster_files(self.temp_dir)
        assert len(base_files) == 1
        assert len(derived_files) == 1
        assert base_file in base_files
        assert derived_file in derived_files

    @patch("dmv_tool.generators.xml_parser.DatamodelParser")
    @patch("dmv_tool.generators.xml_parser.write_to_json_file")
    @patch("dmv_tool.generators.xml_parser.get_base_and_derived_cluster_files")
    def test_process_cluster_files_success(
        self, mock_get_files, mock_write, mock_parser_class
    ):
        mock_get_files.return_value = (["base.xml"], ["derived.xml"])
        mock_cluster = Mock()
        mock_cluster.to_dict.return_value = {"id": "0x0001", "name": "TestCluster"}
        mock_parser = Mock()
        mock_parser.parse.return_value = [mock_cluster]
        mock_parser_class.return_value.ClusterParser.return_value = mock_parser
        mock_write.return_value = True
        process_cluster_files(self.temp_dir, "output.json")
        mock_get_files.assert_called_once_with(self.temp_dir)
        assert mock_parser.parse.call_count == 2
        mock_write.assert_called_once()

    @patch("dmv_tool.generators.xml_parser.get_base_and_derived_cluster_files")
    def test_process_cluster_files_no_files(self, mock_get_files):
        mock_get_files.return_value = ([], [])
        with pytest.raises(
            Exception, match=f"No cluster XML files found in {self.temp_dir}"
        ):
            process_cluster_files(self.temp_dir, "output.json")

    @patch("dmv_tool.generators.xml_parser.process_device_files")
    @patch("dmv_tool.generators.xml_parser.process_cluster_files")
    @patch("os.makedirs")
    def test_generate_json_success(
        self, mock_makedirs, mock_process_clusters, mock_process_devices
    ):
        chip_path = "/path/to/chip"
        spec_version_dir = "1.4.2"
        output_dir = "output"
        generate_json(chip_path, spec_version_dir, output_dir)
        mock_process_devices.assert_called_once()
        mock_process_clusters.assert_called_once()

    @patch("dmv_tool.generators.xml_parser.DatamodelParser")
    @patch("dmv_tool.generators.xml_parser.process_device_files")
    @patch("dmv_tool.generators.xml_parser.write_to_json_file")
    def test_device_files_success(self, mock_write, mock_process_devices, mock_parser_class):
        mock_parser = Mock()
        mock_parser.parse.return_value = [Mock()]
        mock_parser_class.return_value.DeviceParser.return_value = mock_parser
        process_device_files(self.temp_dir, "output.json")
        mock_write.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
