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
from dmv_tool.validators.conformance_checker import (
    detect_spec_version_from_parsed_data,
    find_client_cluster,
    validate_feature_map,
    validate_feature_specific_elements,
    validate_revisions,
    validate_events_with_warnings,
    validate_cluster,
    validate_single_device_type,
    validate_device_conformance,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")


class TestDetectChipVersionFromParsedData:
    """Test the detect_spec_version_from_parsed_data function."""

    def test_detect_version_1_4_2(self):
        """Test detecting version 1.4.2 from parsed data."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {
                        "0x0028": {
                            "attributes": {
                                "0x0015": {
                                    "SpecificationVersion": 17047552  # 0x01042000 for 1.4.2
                                }
                            }
                        }
                    },
                }
            ]
        }
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.4.2"

    def test_detect_version_1_4(self):
        """Test detecting version 1.4 from parsed data."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {
                        "0x0028": {
                            "attributes": {
                                "0x0015": {
                                    "SpecificationVersion": 17039360  # 0x01040000 for 1.4
                                }
                            }
                        }
                    },
                }
            ]
        }
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.4"

    def test_detect_version_1_3(self):
        """Test detecting version 1.3 from parsed data."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {
                        "0x0028": {
                            "attributes": {
                                "0x0015": {
                                    "SpecificationVersion": 16973824  # 0x01030000 for 1.3
                                }
                            }
                        }
                    },
                }
            ]
        }
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.3"

    def test_detect_unknown_version(self):
        """Test detecting unknown version returns None."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {
                        "0x0028": {
                            "revision": 1
                        }  # Only OnOff cluster, no SpecificationVersion
                    },
                }
            ]
        }
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.5"

    def test_detect_no_basic_info_cluster(self):
        """Test detection when no Basic Information cluster is present."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "clusters": {"0x0006": {"revision": 1}},  # Only OnOff cluster
                }
            ]
        }
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.5"

    def test_detect_empty_data(self):
        """Test detection with empty data."""
        parsed_data = {"endpoints": []}
        result = detect_spec_version_from_parsed_data(parsed_data)
        assert result == "1.5"


class TestFindClientCluster:
    """Test the find_client_cluster function."""

    def test_find_existing_client_cluster(self):
        """Test finding an existing client cluster."""
        endpoint_clusters = {
            "0x001D": {  # Descriptor cluster
                "attributes": {
                    "0x0002": {  # ClientList attribute
                        "ClientList": [{"id": "0x0006", "name": "on_off"}]
                    }
                }
            }
        }
        result = find_client_cluster(endpoint_clusters, "0x0006")
        assert result is True

    def test_find_non_existing_client_cluster(self):
        """Test searching for non-existing client cluster."""
        endpoint_clusters = {"client_clusters": [{"id": "0x0003", "name": "identify"}]}
        result = find_client_cluster(endpoint_clusters, "0x0006")
        assert result is False

    def test_find_client_cluster_empty_list(self):
        """Test searching in empty client cluster list."""
        endpoint_clusters = {"client_clusters": []}
        result = find_client_cluster(endpoint_clusters, "0x0006")
        assert result is False

    def test_find_client_cluster_missing_key(self):
        """Test when client_clusters key is missing."""
        endpoint_clusters = {}
        result = find_client_cluster(endpoint_clusters, "0x0006")
        assert result is False


class TestValidateFeatureMap:
    """Test the validate_feature_map function."""

    def test_validate_matching_features(self):
        """Test validation when actual features match required features."""
        actual_feature_map = "0x0005"  # Binary: 0101 (features 0 and 2)
        required_features = [
            {"id": 1, "code": "LT", "name": "Level"},
            {"id": 3, "code": "FQ", "name": "Frequency"},
        ]
        is_valid, errors = validate_feature_map(
            actual_feature_map, required_features, "0x0008", "level_control"
        )
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_missing_required_features(self):
        """Test validation when required features are missing."""
        actual_feature_map = 1  # Binary: 0001 (only feature 0)
        required_features = [
            {"id": 1, "code": "LT", "name": "Level"},
            {"id": 2, "code": "FQ", "name": "Frequency"},  # Missing
        ]
        is_valid, errors = validate_feature_map(
            actual_feature_map, required_features, "0x0008", "level_control"
        )

        assert is_valid is False
        assert len(errors) > 0
        assert errors[0].get("message") == "Required feature Frequency (2) is missing"

    def test_validate_extra_features_allowed(self):
        """Test validation with extra features (should be allowed)."""
        actual_feature_map = "0x000F"  # Binary: 1111 (features 0,1,2,3)
        required_features = [{"id": 1, "code": "LT", "name": "Level"}]
        is_valid, errors = validate_feature_map(
            actual_feature_map, required_features, "0x0008", "level_control"
        )
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_no_required_features(self):
        """Test validation when no features are required."""
        actual_feature_map = "0x0000"
        required_features = []
        is_valid, errors = validate_feature_map(
            actual_feature_map, required_features, "0x0008", "level_control"
        )
        assert is_valid is True
        assert len(errors) == 0


class TestValidateFeatureSpecificElements:
    """Test the validate_feature_specific_elements function."""

    def test_validate_elements_with_features(self):
        """Test validation of feature-specific elements."""
        actual_cluster = {
            "attributes": [
                {"id": "0x0000", "name": "on_off"},
                {"id": "0x0001", "name": "global_scene_control"},
            ],
            "commands": [
                {"id": "0x0000", "name": "off"},
                {"id": "0x0001", "name": "on"},
            ],
        }
        required_features = [
            {
                "id": 0,
                "code": "LT",
                "name": "Lighting",
                "elements": {
                    "attributes": [{"id": "0x0001", "name": "global_scene_control"}],
                    "commands": [{"id": "0x0001", "name": "on"}],
                },
            }
        ]
        is_valid, errors = validate_feature_specific_elements(
            actual_cluster, required_features, "0x0006", "on_off"
        )
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_missing_feature_elements(self):
        """Test validation when feature-specific elements are missing."""
        actual_cluster = {
            "attributes": [{"id": "0x0000", "name": "on_off"}],
            "commands": [
                {"id": "0x0000", "name": "off"},
                {"id": "0x0001", "name": "on"},
            ],
            "features": {"FeatureMap": {"FeatureMap": 7}},
        }
        required_features = [
            {
                "id": 1,
                "code": "LT",
                "name": "Lighting",
                "required": True,
                "attributes": [{"id": "0x0001", "name": "global_scene_control"}],
                "commands": [{"id": "0x0001", "name": "on"}],
            }
        ]
        is_valid, errors = validate_feature_specific_elements(
            actual_cluster, required_features, "0x0006", "on_off"
        )
        assert is_valid is False
        assert len(errors) > 0
        assert (
            errors[0].get("message")
            == "Feature 'Lighting' is present but required attribute 'global_scene_control' (0x0001) is missing"
        )


class TestValidateRevisions:
    """Test the validate_revisions function."""

    def test_validate_matching_revisions(self):
        """Test validation when revisions match."""
        is_valid, errors = validate_revisions("2", "2", "cluster", "0x0006", "on_off")
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_higher_actual_revision(self):
        """Test validation when actual revision is higher (should pass)."""
        is_valid, errors = validate_revisions("3", "2", "cluster", "0x0006", "on_off")
        assert is_valid is False
        assert len(errors) > 0
        assert (
            errors[0].get("message")
            == "Cluster on_off has revision 3, but requires exactly revision 2"
        )

    def test_validate_lower_actual_revision(self):
        """Test validation when actual revision is lower (should fail)."""
        is_valid, errors = validate_revisions("1", "2", "cluster", "0x0006", "on_off")
        assert is_valid is False
        assert len(errors) > 0
        assert (
            errors[0].get("message")
            == "Cluster on_off has revision 1, but requires exactly revision 2"
        )

    def test_validate_invalid_revision_format(self):
        """Test validation with invalid revision format."""
        is_valid, errors = validate_revisions(
            "invalid", "2", "cluster", "0x0006", "on_off"
        )
        assert is_valid is False
        assert len(errors) > 0


class TestValidateEventsWithWarnings:
    """Test the validate_events_with_warnings function."""

    def test_validate_events_all_present(self):
        """Test when all required events are present."""
        actual_cluster = {
            "events": {
                "EventList": {
                    "EventList": [
                        {"id": "0x0000", "name": "startup"},
                        {"id": "0x0001", "name": "shutdown"},
                    ]
                }
            }
        }
        required_events = [
            {"id": "0x0000", "name": "startup"},
            {"id": "0x0001", "name": "shutdown"},
        ]
        warnings = validate_events_with_warnings(
            actual_cluster, required_events, "0x0028", "basic_information"
        )
        assert len(warnings) == 3  # 2 event requirements and 1 event info warning

    def test_validate_events_missing_some(self):
        """Test when some required events are missing."""
        actual_cluster = {
            "events": {
                "EventList": {"EventList": [{"id": "0x0001", "name": "shutdown"}]}
            }
        }
        required_events = [
            {"id": "0x0000", "name": "startup"},
        ]
        warnings = validate_events_with_warnings(
            actual_cluster, required_events, "0x0028", "basic_information"
        )
        assert len(warnings) > 0
        event_warning = warnings[1]
        assert (
            event_warning.get("message")
            == "Required event startup (0x0000) not found in wildcard logs"
        )

    def test_validate_events_no_events_section(self):
        """Test when events section is missing."""
        actual_cluster = {}
        required_events = [{"id": "0x0000", "name": "startup"}]
        warnings = validate_events_with_warnings(
            actual_cluster, required_events, "0x0028", "basic_information"
        )
        assert len(warnings) > 0


class TestValidateCluster:
    """Test the validate_cluster function."""

    def test_validate_compliant_cluster(self):
        """Test validation of a fully compliant cluster."""
        endpoint_clusters = {
            "0x0006": {
                "name": "on_off",
                "revision": 6,
                "feature_map": "0x0000",
                "attributes": {
                    "AttributeList": {
                        "AttributeList": [
                            {"id": "0x0000", "name": "on_off"},
                        ]
                    }
                },
                "commands": {
                    "GeneratedCommandList": {
                        "GeneratedCommandList": [
                            {"id": "0x0000", "name": "off"},
                            {"id": "0x0001", "name": "on"},
                        ]
                    },
                    "AcceptedCommandList": {
                        "AcceptedCommandList": [
                            {"id": "0x0000", "name": "off"},
                            {"id": "0x0001", "name": "on"},
                        ]
                    },
                },
                "events": {},
            }
        }

        required_cluster = {
            "id": "0x0006",
            "name": "on_off",
            "revision": "6",
            "required": True,
            "type": "server",
            "attributes": [{"id": "0x0000", "name": "on_off"}],
            "commands": [
                {"id": "0x0000", "name": "off"},
                {"id": "0x0001", "name": "on"},
            ],
            "events": [],
            "features": [],
        }

        result = validate_cluster(endpoint_clusters, required_cluster)

        assert result["is_compliant"] is True
        assert len(result["missing_elements"]) == 0

    def test_validate_missing_required_cluster(self):
        """Test validation when required cluster is missing."""
        endpoint_clusters = {}

        required_cluster = {
            "id": "0x0006",
            "name": "on_off",
            "required": True,
            "type": "server",
        }

        result = validate_cluster(endpoint_clusters, required_cluster)

        assert result["is_compliant"] is False
        assert len(result["missing_elements"]) > 0
        assert "Required server cluster" in result["missing_elements"][0]["message"]

    def test_validate_optional_missing_cluster(self):
        """Test validation when optional cluster is missing (should pass)."""
        endpoint_clusters = {}

        required_cluster = {
            "id": "0x0006",
            "name": "on_off",
            "required": False,
            "type": "server",
        }

        result = validate_cluster(endpoint_clusters, required_cluster)

        assert result["is_compliant"] is True
        assert (
            len(result["missing_elements"]) == 1
        )  # Contains info about optional cluster
        assert "Optional server cluster" in result["missing_elements"][0]["message"]

    def test_validate_client_cluster(self):
        """Test validation of client cluster."""
        endpoint_clusters = {
            "0x001D": {  # Descriptor cluster
                "attributes": {
                    "0x0002": {  # ClientList attribute
                        "ClientList": [{"id": "0x0006", "name": "on_off"}]
                    }
                }
            }
        }

        required_cluster = {
            "id": "0x0006",
            "name": "on_off",
            "required": True,
            "type": "client",
        }

        result = validate_cluster(endpoint_clusters, required_cluster)

        assert result["is_compliant"] is True
        assert len(result["missing_elements"]) == 0


class TestValidateSingleDeviceType:
    """Test the validate_single_device_type function."""

    def test_validate_compliant_device(self):
        """Test validation of compliant device type."""
        endpoint = {
            "clusters": {
                "0x001D": {
                    "name": "descriptor",
                    "revision": 2,
                    "feature_map": "0x0000",
                    "attributes": {
                        "0x0000": {
                            "DeviceTypeList": [
                                {
                                    "DeviceType": {"id": "0x0016", "name": "root_node"},
                                    "Revision": 3,
                                },
                            ]
                        },
                        "AttributeList": {
                            "AttributeList": [
                                {"id": "0x0000", "name": "device_type_list"},
                            ]
                        },
                    },
                    "commands": {},
                    "events": {},
                }
            },
            "client_clusters": [],
        }

        device_requirements = {
            "id": "0x0016",
            "name": "root_node",
            "revision": "3",
            "clusters": [
                {
                    "id": "0x001D",
                    "name": "descriptor",
                    "revision": "2",
                    "required": True,
                    "type": "server",
                    "attributes": [{"id": "0x0000", "name": "device_type_list"}],
                    "commands": [],
                    "events": [],
                    "features": [],
                }
            ],
        }

        result = validate_single_device_type(endpoint, 0x0016, device_requirements)
        assert result["is_compliant"] is True
        assert len(result["missing_elements"]) == 0

    def test_validate_missing_device_type(self):
        """Test validation when device type is not found in requirements."""
        endpoint = {"device_type": {"id": "0x9999", "name": "unknown_device"}}

        device_requirements = {
            "id": "0x9999",
            "name": "unknown_device",
            "revision": "1",
            "clusters": [],
        }

        result = validate_single_device_type(endpoint, "0x9999", device_requirements)

        assert result["is_compliant"] is False
        assert len(result["revision_issues"]) > 0


class TestValidateDeviceConformance:
    """Test the validate_device_conformance function."""

    def test_validate_compliant_device_data(self):
        """Test validation of fully compliant device data."""
        parsed_data = {
            "endpoints": [
                {
                    "id": 0,
                    "device_type": {"id": "0x0016", "name": "root_node"},
                    "clusters": {
                        "0x001D": {
                            "name": "descriptor",
                            "revision": 2,
                            "feature_map": "0x0000",
                            "attributes": {},
                            "commands": {},
                            "events": {},
                        }
                    },
                    "client_clusters": [],
                }
            ]
        }

        result = validate_device_conformance(parsed_data, "1.4.2")

        assert result.get("summary").get("total_endpoints") == 1
        assert result.get("summary").get("non_compliant_endpoints") == 1


if __name__ == "__main__":
    pytest.main([__file__])
