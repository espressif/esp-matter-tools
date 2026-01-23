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
from dmv_tool.utils.helpers import convert_to_int, convert_to_hex
from dmv_tool.configs.constants import DEFAULT_OUTPUT_DIR, DEFAULT_REPORT_FILE
from typing import List, Tuple

from .utils import (
    find_element_in_list,
    get_nested_list,
    process_element_list,
    convert_specification_version,
    find_duplicates_in_element_list,
)
from .reporting import generate_conformance_report
from .constants import (
    DESCRIPTOR_CLUSTER_ID,
    DESCRIPTOR_CLIENT_LIST_ATTRIBUTE_ID,
    BASIC_INFORMATION_CLUSTER_ID,
    SPECIFICATION_VERSION_ATTRIBUTE_ID,
    DEVICE_TYPE_LIST_ATTRIBUTE_ID,
)

from dmv_tool.parsers.wildcard_logs import parse_datamodel_logs

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def detect_spec_version_from_parsed_data(parsed_data):
    """Detect spec version from SpecificationVersion in parsed data.

    Args:
        parsed_data: Already parsed device data

    Returns:
        Detected version string or "1.5" if not found
    """
    root_node_endpoint = next(
        (
            endpoint
            for endpoint in parsed_data.get("endpoints", [])
            if endpoint.get("id") == 0
        ),
        None,
    )
    detected_version = "1.5"
    if root_node_endpoint:
        basic_info_cluster = root_node_endpoint.get("clusters", {}).get(
            BASIC_INFORMATION_CLUSTER_ID, {}
        )
        if not basic_info_cluster:
            logger.warning("No Basic Information cluster found in parsed data")
            return detected_version
        spec_attribute_value = (
            basic_info_cluster.get("attributes", {})
            .get(SPECIFICATION_VERSION_ATTRIBUTE_ID, {})
            .get("SpecificationVersion", None)
        )
        if not spec_attribute_value:
            logger.warning(
                "No SpecificationVersion attribute found in Basic Information cluster"
            )
            return detected_version
        detected_version = convert_specification_version(spec_attribute_value)
        if not detected_version:
            logger.warning(
                "Invalid SpecificationVersion value found in Basic Information cluster"
            )
        return detected_version
    return detected_version


def find_client_cluster(endpoint_clusters: dict, client_cluster_id: str) -> bool:
    """Find a client cluster by searching through all server clusters' ClientList.

    Args:
        endpoint_clusters: Dictionary of all clusters in the endpoint
        client_cluster_id: ID of the client cluster to find

    Returns:
        True if client cluster is found, False otherwise
    """

    descriptor_cluster = endpoint_clusters.get(DESCRIPTOR_CLUSTER_ID, {})
    if not descriptor_cluster:
        logger.warning("No Descriptor cluster found in endpoint")
        return False
    client_list_attribute = descriptor_cluster.get("attributes", {}).get(
        DESCRIPTOR_CLIENT_LIST_ATTRIBUTE_ID, {}
    )
    if not client_list_attribute:
        logger.warning("No ClientList attribute found in Descriptor cluster")
        return False
    client_list = client_list_attribute.get("ClientList", [])
    if not client_list:
        logger.warning("No ClientList found in Descriptor cluster")
        return False
    for client in client_list:
        if client.get("id") == client_cluster_id:
            logger.debug(
                f"Client cluster {client_cluster_id} found in Descriptor cluster on endpoint."
            )
            return True
    return False


def validate_feature_map(
    actual_feature_map: str,
    required_features: list,
    cluster_id: str,
    cluster_name: str,
    require_presence: bool = True,
) -> Tuple[bool, List[dict]]:
    """Validate features using bitwise operations on feature_map.

    Args:
        actual_feature_map: The actual feature map value from device
        required_features: List of required features with IDs and names
        cluster_id: Cluster identifier for error reporting
        cluster_name: Cluster name for error reporting
        require_presence: Whether features must be present or just validated if present

    Returns:
        Tuple of (is_valid, missing_features_list: List[dict])
    """
    if not required_features:
        return True, []

    missing_features = []

    try:
        feature_map_value = convert_to_int(actual_feature_map)
        if feature_map_value is None:
            return False, [
                {
                    "type": "feature",
                    "message": f"Invalid feature_map type {type(actual_feature_map)} in cluster {cluster_id}",
                }
            ]

        for required_feature in required_features:
            if not isinstance(required_feature, dict):
                logger.error(
                    f"Invalid feature format in cluster {cluster_id}: {required_feature}"
                )
                continue

            feature_id = required_feature.get("id")
            feature_name = required_feature.get("name", "unknown")

            if not feature_id:
                logger.error(f"Missing feature ID in cluster {cluster_id}")
                continue

            feature_bitmask = convert_to_int(feature_id)
            if feature_bitmask is None:
                logger.error(
                    f"Invalid feature ID format '{feature_id}' in cluster {cluster_id}"
                )
                continue

            feature_is_present = bool(feature_map_value & feature_bitmask)

            if require_presence and not feature_is_present:
                logger.error(f"Required feature {feature_name} ({feature_id}) is missing")
                missing_features.append(
                    {
                        "type": "feature",
                        "id": feature_id,
                        "name": feature_name,
                        "cluster_id": cluster_id,
                        "cluster_name": cluster_name,
                        "feature_bitmask": convert_to_hex(feature_bitmask),
                        "feature_map_value": convert_to_hex(feature_map_value),
                        "check_result": convert_to_hex(
                            feature_map_value & feature_bitmask
                        ),
                        "message": f"Required feature {feature_name} ({feature_id}) is missing",
                    }
                )

        return len(missing_features) == 0, missing_features

    except Exception as e:
        raise Exception(f"Feature validation error: {str(e)}") from e


def validate_feature_specific_attributes(
    actual_cluster: dict,
    required_feature: dict,
) -> List[dict]:
    """Validate feature-specific attributes.

    Args:
        actual_cluster: The cluster data from device
        required_feature: The required feature
    """
    missing_attributes = []
    cluster_id = actual_cluster.get("id")
    cluster_name = actual_cluster.get("name")
    feature_id = required_feature.get("id")
    feature_name = required_feature.get("name")
    for required_attr in required_feature.get("attributes", []):
        if not isinstance(required_attr, dict):
            logger.error(
                f"Invalid attribute format in cluster {cluster_id}: {required_attr}"
            )
            continue

        attr_id = required_attr["id"]
        attr_name = required_attr["name"]

        found = False

        if attr_id in actual_cluster.get("attributes", {}):
            found = True

        if not found:
            attr_list = get_nested_list(
                actual_cluster,
                "attributes",
                "AttributeList",
                "AttributeList",
            )
            found = find_element_in_list(attr_list, attr_id)

        if not found:
            logger.error(
                f"Feature '{feature_name}' is present but required attribute '{attr_name}' ({attr_id}) is missing"
            )
            missing_attributes.append(
                {
                    "type": "feature_attribute",
                    "id": attr_id,
                    "name": attr_name,
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "feature_id": feature_id,
                    "feature_name": feature_name,
                    "message": f"Feature '{feature_name}' is present but required attribute '{attr_name}' ({attr_id}) is missing",
                }
            )
    return missing_attributes


def validate_feature_specific_commands(
    actual_cluster: dict,
    required_feature: dict,
) -> List[dict]:
    """Validate feature-specific commands.

    Args:
        actual_cluster: The cluster data from device
        required_feature: The required feature
    """
    missing_commands = []
    cluster_id = actual_cluster.get("id")
    cluster_name = actual_cluster.get("name")
    feature_id = required_feature.get("id")
    feature_name = required_feature.get("name")
    for required_cmd in required_feature.get("commands", []):
        if not isinstance(required_cmd, dict):
            logger.error(
                f"Invalid command format in cluster {cluster_id}: {required_cmd}"
            )
            continue

        cmd_id = required_cmd["id"]
        cmd_name = required_cmd["name"]

        found = False
        for cmd_list_name in [
            "GeneratedCommandList",
            "AcceptedCommandList",
        ]:
            cmd_list = get_nested_list(
                actual_cluster, "commands", cmd_list_name, cmd_list_name
            )
            if find_element_in_list(cmd_list, cmd_id):
                found = True
                break

        if not found:
            logger.error(
                f"Feature '{feature_name}' is present but required command '{cmd_name}' ({cmd_id}) is missing"
            )
            missing_commands.append(
                {
                    "type": "feature_command",
                    "id": cmd_id,
                    "name": cmd_name,
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "feature_id": feature_id,
                    "feature_name": feature_name,
                    "message": f"Feature '{feature_name}' is present but required command '{cmd_name}' ({cmd_id}) is missing",
                }
            )

    return missing_commands


def validate_feature_specific_events(
    actual_cluster: dict,
    required_feature: dict,
) -> List[dict]:
    """Validate feature-specific events.

    Args:
        actual_cluster: The cluster data from device
        required_feature: The required feature
    """
    missing_events = []
    cluster_id = actual_cluster.get("id")
    cluster_name = actual_cluster.get("name")
    feature_id = required_feature.get("id")
    feature_name = required_feature.get("name")
    for required_event in required_feature.get("events", []):
        if not isinstance(required_event, dict):
            logger.error(
                f"Invalid event format in cluster {cluster_id}: {required_event}"
            )
            continue

        event_id = required_event["id"]
        event_name = required_event["name"]

        event_list = get_nested_list(actual_cluster, "events", "EventList", "EventList")
        found = find_element_in_list(event_list, event_id)

        if not found:
            logger.error(
                f"Feature '{feature_name}' is present but required event '{event_name}' ({event_id}) is missing"
            )
            missing_events.append(
                {
                    "type": "feature_event",
                    "id": event_id,
                    "name": event_name,
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "feature_id": feature_id,
                    "feature_name": feature_name,
                    "message": f"Feature '{feature_name}' is present but required event '{event_name}' ({event_id}) is missing",
                }
            )
    return missing_events


def validate_feature_specific_elements(
    actual_cluster: dict,
    required_features: list,
    cluster_id: str,
    cluster_name: str,
) -> Tuple[bool, List[dict]]:
    """Validate feature-specific attributes, commands, and events when features are present.

    Args:
        actual_cluster: The cluster data from device
        required_features: List of required features
        cluster_id: Cluster identifier
        cluster_name: Cluster name

    Returns:
        Tuple of (is_valid, missing_elements_list: List[dict])
    """
    if not required_features:
        return True, []

    missing_elements = []

    try:
        feature_map_data = actual_cluster.get("features", {}).get("FeatureMap", {})
        if (
            not isinstance(feature_map_data, dict)
            or "FeatureMap" not in feature_map_data
        ):
            return True, []

        actual_feature_map = feature_map_data["FeatureMap"]

        feature_map_value = convert_to_int(actual_feature_map)
        logger.debug(f"Feature map value '{feature_map_value}' in cluster {cluster_id}")
        if feature_map_value is None:
            return True, []

        for required_feature in required_features:
            feature_id = required_feature.get("id", None)
            if not feature_id:
                logger.error(f"Missing feature ID in cluster {cluster_id}")
                continue
            feature_name = required_feature.get("name", "unknown")
            # Required feature means that feature is mandatory for the specific device type
            feature_required = required_feature.get("required", True)

            feature_bitmask = convert_to_int(feature_id)
            if feature_bitmask is None:
                logger.error(
                    f"Invalid feature ID format '{feature_id}' in cluster {cluster_id}"
                )
                continue

            feature_is_present = bool(feature_map_value & feature_bitmask)
            # Only validate features related data if feature is present or required
            if feature_is_present or (feature_required is True):
                if feature_is_present:
                    logger.debug(f"Validating attributes for feature '{feature_name}'")
                    missing_attributes = validate_feature_specific_attributes(
                        actual_cluster, required_feature
                    )
                    missing_elements.extend(missing_attributes)

                    logger.debug(f"Validating commands for feature '{feature_name}'")
                    missing_commands = validate_feature_specific_commands(
                        actual_cluster, required_feature
                    )
                    missing_elements.extend(missing_commands)

                    logger.debug(f"Validating events for feature '{feature_name}'")
                    missing_events = validate_feature_specific_events(
                        actual_cluster, required_feature
                    )
                    missing_elements.extend(missing_events)

        return len(missing_elements) == 0, missing_elements

    except Exception as e:
        raise Exception(f"Feature-specific validation error: {str(e)}") from e


def validate_revisions(
    actual_revision: str,
    required_revision: str,
    item_type: str,
    item_id: str,
    item_name: str,
) -> Tuple[bool, List[dict]]:
    """Validate revision compatibility - revisions must match exactly.

    Args:
        actual_revision: The actual revision from device
        required_revision: The required revision
        item_type: Type of item being validated
        item_id: ID of the item
        item_name: Name of the item

    Returns:
        Tuple of (is_valid, revision_issues_list: List[dict])
    """
    revision_issues = []

    try:
        actual_rev = convert_to_int(actual_revision)
        required_rev = convert_to_int(required_revision)

        if actual_rev is None or required_rev is None:
            return False, [
                {
                    "type": "revision_error",
                    "message": f"Invalid revision format: {actual_revision} or {required_revision}",
                }
            ]

        if actual_rev != required_rev:
            logger.error(
                f"{item_type.title()} {item_name} has revision {actual_rev}, but requires exactly revision {required_rev}"
            )
            revision_issues.append(
                {
                    "type": "revision_mismatch",
                    "item_type": item_type,
                    "item_id": item_id,
                    "item_name": item_name,
                    "actual_revision": actual_rev,
                    "required_revision": required_rev,
                    "severity": "error",
                    "message": f"{item_type.title()} {item_name} has revision {actual_rev}, but requires exactly revision {required_rev}",
                }
            )

        return actual_rev == required_rev, revision_issues

    except Exception as e:
        raise Exception(
            f"Revision validation error for {item_type} {item_name}: {str(e)}"
        ) from e


def validate_events_with_warnings(
    actual_cluster: dict,
    required_events: list,
    cluster_id: str,
    cluster_name: str,
) -> List[dict]:
    """Validate events and provide warnings (not conformance failures).

    Args:
        actual_cluster: The cluster data from device
        required_events: List of required events
        cluster_id: Cluster identifier
        cluster_name: Cluster name

    Returns:
        List of event warnings: List[dict]
    """
    event_warnings = []

    if not required_events:
        return event_warnings

    present_events = []

    event_list = get_nested_list(actual_cluster, "events", "EventList", "EventList")
    present_events = process_element_list(event_list)

    event_warnings.append(
        {
            "type": "event_info",
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "severity": "info",
            "message": f"Event validation skipped for cluster {cluster_name} - wildcard logs don't typically contain events",
        }
    )

    for required_event in required_events:
        event_id = required_event.get("id")
        event_name = required_event.get("name", "unknown")

        is_present = event_id in present_events

        if event_id in [event.get("event_id", None) for event in event_warnings]:
            logger.debug(
                f"Event {event_name} ({event_id}) already added to event_warnings"
            )
            continue

        event_warnings.append(
            {
                "type": "event_requirement",
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "event_id": event_id,
                "event_name": event_name,
                "is_present": is_present,
                "severity": "warning" if not is_present else "info",
                "message": f"Required event {event_name} ({event_id}) {'found' if is_present else 'not found in wildcard logs'}",
            }
        )

    if present_events:
        if event_id in [event.get("event_id", None) for event in event_warnings]:
            logger.debug(
                f"Event {event_name} ({event_id}) already added to event_warnings"
            )
            return event_warnings

        event_warnings.append(
            {
                "type": "event_found",
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "present_events": present_events,
                "severity": "info",
                "message": f"Found {len(present_events)} events in wildcard logs: {', '.join(present_events)}",
            }
        )

    return event_warnings


def load_chip_validation_data(spec_version: str) -> List[dict]:
    """Load validation JSONs for validation.

    Args:
        spec_version: Version to load specific version validation JSON file

    Returns:
        List of device type validation JSONs, empty list if error occurs
    """
    if not spec_version:
        logger.error("spec_version parameter is required")
        return []

    try:
        file_path = f"{BASE_DIR}/data/validation_data_{spec_version}.json"

        with open(file_path, "r", encoding="utf-8") as f:
            requirements = json.load(f)

            if not isinstance(requirements, list):
                logger.error(
                    f"Invalid requirements format: expected list, got {type(requirements)}"
                )
                return []

            valid_requirements = []
            for i, req in enumerate(requirements):
                if not isinstance(req, dict):
                    logger.error(
                        f"Skipping invalid requirement at index {i}: not a dict"
                    )
                    continue
                if "id" not in req:
                    logger.error(
                        f"Skipping requirement at index {i}: missing 'id' field"
                    )
                    continue
                valid_requirements.append(req)
            return valid_requirements

    except FileNotFoundError:
        logger.error(f"Required validation JSON file not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(
            f"Error parsing required validation JSON for version {spec_version}: {e}"
        )
        return []
    except Exception as e:
        raise Exception(
            f"Unexpected error loading required validation JSON for version {spec_version}: {e}"
        ) from e


def validate_cluster(
    endpoint_clusters: dict,
    required_cluster: dict,
) -> dict:
    """Validate a cluster against its requirements.

    Args:
        endpoint_clusters: Dictionary of all clusters in the endpoint
        required_cluster: Required cluster configuration

    Returns:
        Validation result with conformance status and missing elements
    """
    if not isinstance(required_cluster, dict):
        raise ValueError(
            f"required_cluster must be a dict, got {type(required_cluster)}"
        )

    cluster_id = required_cluster["id"]
    cluster_name = required_cluster["name"]
    cluster_type = required_cluster.get("type", "server")
    required_revision = required_cluster.get("revision")
    cluster_required = required_cluster.get("required", True)

    result = {
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "cluster_type": cluster_type,
        "is_compliant": True,
        "missing_elements": [],
        "duplicate_elements": [],
        "revision_issues": [],
        "event_warnings": [],
        "cluster_required": cluster_required,
    }

    cluster_exists = False
    actual_cluster = None

    if cluster_type == "client":
        cluster_exists = find_client_cluster(endpoint_clusters, cluster_id)
    else:
        cluster_exists = cluster_id in endpoint_clusters
        if cluster_exists:
            actual_cluster = endpoint_clusters[cluster_id]

    if cluster_required is True:
        # Cluster is required and must be compliant
        if not cluster_exists:
            logger.error(f"Required {cluster_type} cluster {cluster_name} is missing")
            result["is_compliant"] = False
            result["missing_elements"].append(
                {
                    "type": "cluster",
                    "id": cluster_id,
                    "name": cluster_name,
                    "cluster_type": cluster_type,
                    "message": f"Required {cluster_type} cluster {cluster_name} is missing",
                }
            )
            return result
    elif cluster_required == "conditional":
        # Cluster is optional, but if present, must be compliant
        if not cluster_exists:
            result["is_compliant"] = True
            result["missing_elements"].append(
                {
                    "type": "info",
                    "id": cluster_id,
                    "name": cluster_name,
                    "cluster_type": cluster_type,
                    "message": f"Conditional {cluster_type} cluster {cluster_name} not present (OK)",
                }
            )
            return result
    elif cluster_required is False:
        # Cluster is optional and can be ignored
        if not cluster_exists:
            result["is_compliant"] = True
            result["missing_elements"].append(
                {
                    "type": "info",
                    "id": cluster_id,
                    "name": cluster_name,
                    "cluster_type": cluster_type,
                    "message": f"Optional {cluster_type} cluster {cluster_name} not present (OK)",
                }
            )
            return result

    if cluster_type == "client":
        logger.debug(f"Skipping client cluster {cluster_name} validation")
        return result

    actual_revision = None
    cluster_revision_data = actual_cluster.get("revisions", {}).get(
        "ClusterRevision", {}
    )
    if (
        isinstance(cluster_revision_data, dict)
        and "ClusterRevision" in cluster_revision_data
    ):
        actual_revision = cluster_revision_data["ClusterRevision"]

    if actual_revision is not None and required_revision is not None:
        revision_compliant, revision_issues = validate_revisions(
            actual_revision, required_revision, "cluster", cluster_id, cluster_name
        )
        if not revision_compliant:
            result["is_compliant"] = False
        result["revision_issues"].extend(revision_issues)

    expected_attributes = required_cluster.get("attributes", [])
    actual_on_device_attributes = get_nested_list(
        actual_cluster, "attributes", "AttributeList", "AttributeList"
    )

    for required_attr in expected_attributes:
        if not isinstance(required_attr, dict):
            logger.error(f"Attribute {required_attr} is not a dict, skipping")
            continue

        attr_id = required_attr["id"]
        attr_name = required_attr["name"]

        found = False

        if attr_id in actual_cluster.get("attributes", {}):
            found = True

        if not found:
            found = find_element_in_list(actual_on_device_attributes, attr_id)

        if not found:
            logger.error(f"Required attribute {attr_name} ({attr_id}) is missing")
            result["is_compliant"] = False
            result["missing_elements"].append(
                {
                    "type": "attribute",
                    "id": attr_id,
                    "name": attr_name,
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "message": f"Required attribute {attr_name} ({attr_id}) is missing",
                }
            )

    expected_commands = required_cluster.get("commands", [])
    actual_on_device_commands = []
    for cmd_list_name in ["GeneratedCommandList", "AcceptedCommandList"]:
        cmd_list = get_nested_list(
            actual_cluster, "commands", cmd_list_name, cmd_list_name
        )
        actual_on_device_commands.extend(cmd_list)

    for required_cmd in expected_commands:
        if not isinstance(required_cmd, dict):
            logger.error(f"Command {required_cmd} is not a dict, skipping")
            continue

        cmd_id = required_cmd["id"]
        cmd_name = required_cmd["name"]

        for actual_cmd in actual_on_device_commands:
            found = False
            if isinstance(actual_cmd, dict):
                actual_cmd_id = actual_cmd.get("id", None)
                actual_cmd_name = actual_cmd.get("name", None)
                # Unknown command means chip-tool not able to recognize the command, but it is present on the device
                if actual_cmd_id == cmd_id and (
                    actual_cmd_name == cmd_name
                    or actual_cmd_name.lower() == "unknown"
                    or not actual_cmd_name
                ):
                    found = True
                    break
            elif isinstance(actual_cmd, int) and actual_cmd == convert_to_int(cmd_id):
                found = True
                break
            elif convert_to_int(actual_cmd) == convert_to_int(cmd_id):
                found = True
                break

        if not found:
            logger.error(f"Required command {cmd_name} ({cmd_id}) is missing")
            result["is_compliant"] = False
            result["missing_elements"].append(
                {
                    "type": "command",
                    "id": cmd_id,
                    "name": cmd_name,
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "message": f"Required command {cmd_name} ({cmd_id}) is missing",
                }
            )

    required_features = required_cluster.get("features", [])
    if required_features:
        feature_map_data = actual_cluster.get("features", {}).get("FeatureMap", {})
        logger.debug(f"Feature map data: {feature_map_data} have_feature_map: {feature_map_data.get('FeatureMap')}")

        device_type_required_features = []
        conditional_features = []

        for feature in required_features:
            if not isinstance(feature, dict):
                logger.error(f"Feature {feature} is not a dict, skipping")
                continue

            feature_required = feature.get("required", True)

            if feature_required is True:
                device_type_required_features.append(feature)
            elif feature_required == "conditional":
                conditional_features.append(feature)
            elif feature_required is False:
                conditional_features.append(feature)

        actual_feature_map = 0
        if isinstance(feature_map_data, dict):
            feature_map_value = feature_map_data.get("FeatureMap")
            if feature_map_value is not None:
                actual_feature_map = feature_map_value

        actual_feature_map_str = str(actual_feature_map)

        if device_type_required_features:
            feature_compliant, missing_features = validate_feature_map(
                actual_feature_map_str,
                device_type_required_features,
                cluster_id,
                cluster_name,
                require_presence=True,
            )
            if not feature_compliant:
                result["is_compliant"] = False
                result["missing_elements"].extend(missing_features)

            all_features_to_check = device_type_required_features + conditional_features
            feature_specific_compliant, feature_specific_missing = (
                validate_feature_specific_elements(
                    actual_cluster, all_features_to_check, cluster_id, cluster_name
                )
            )

            for missing_element in feature_specific_missing:
                if missing_element["type"] == "feature_event":
                    if missing_element["id"] in [
                        event.get("event_id", None)
                        for event in result["event_warnings"]
                    ]:
                        logger.debug(
                            f"Event {missing_element['name']} ({missing_element['id']}) already added to event_warnings"
                        )
                        continue

                    result["event_warnings"].append(
                        {
                            "type": "event_requirement",
                            "cluster_id": cluster_id,
                            "cluster_name": cluster_name,
                            "event_id": missing_element["id"],
                            "event_name": missing_element["name"],
                            "severity": "warning",
                            "message": missing_element["message"],
                        }
                    )
                else:
                    if not feature_specific_compliant:
                        result["is_compliant"] = False
                        result["missing_elements"].append(missing_element)

    required_events = required_cluster.get("events", [])
    event_warnings = validate_events_with_warnings(
        actual_cluster, required_events, cluster_id, cluster_name
    )
    result["event_warnings"].extend(event_warnings)

    # Check for duplicate attributes
    attr_list = actual_on_device_attributes
    duplicate_attrs = find_duplicates_in_element_list(attr_list)
    for dup_attr in duplicate_attrs:
        logger.error(
            f"Duplicate attribute {dup_attr['name']} ({dup_attr['id']}) found {dup_attr['count']} times"
        )
        result["is_compliant"] = False
        result["duplicate_elements"].append(
            {
                "type": "duplicate_attribute",
                "id": dup_attr["id"],
                "name": dup_attr["name"],
                "count": dup_attr["count"],
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "message": f"Duplicate attribute {dup_attr['name']} ({dup_attr['id']}) found {dup_attr['count']} times",
            }
        )

    # Check for duplicate commands in AcceptedCommandList
    accepted_cmd_list = get_nested_list(
        actual_cluster, "commands", "AcceptedCommandList", "AcceptedCommandList"
    )
    duplicate_accepted_cmds = find_duplicates_in_element_list(accepted_cmd_list)
    for dup_cmd in duplicate_accepted_cmds:
        logger.error(
            f"Duplicate command {dup_cmd['name']} ({dup_cmd['id']}) found {dup_cmd['count']} times"
        )
        result["is_compliant"] = False
        result["duplicate_elements"].append(
            {
                "type": "duplicate_command",
                "id": dup_cmd["id"],
                "name": dup_cmd["name"],
                "count": dup_cmd["count"],
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "list_type": "AcceptedCommandList",
                "message": f"Duplicate command {dup_cmd['name']} ({dup_cmd['id']}) found {dup_cmd['count']} times in AcceptedCommandList",
            }
        )

    # Check for duplicate commands in GeneratedCommandList
    generated_cmd_list = get_nested_list(
        actual_cluster, "commands", "GeneratedCommandList", "GeneratedCommandList"
    )
    duplicate_generated_cmds = find_duplicates_in_element_list(generated_cmd_list)
    for dup_cmd in duplicate_generated_cmds:
        result["is_compliant"] = False
        result["duplicate_elements"].append(
            {
                "type": "duplicate_command",
                "id": dup_cmd["id"],
                "name": dup_cmd["name"],
                "count": dup_cmd["count"],
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "list_type": "GeneratedCommandList",
                "message": f"Duplicate command {dup_cmd['name']} ({dup_cmd['id']}) found {dup_cmd['count']} times in GeneratedCommandList",
            }
        )

    return result


def validate_single_device_type(
    endpoint: dict,
    device_type_id: str,
    device_requirements: list,
) -> dict:
    """Validate a single device type against its Matter Specification requirements.

    Args:
        endpoint: The endpoint data containing clusters
        device_type_id: The device type ID to validate
        device_requirements: The Matter Specification requirements for this device type

    Returns:
        Validation result with conformance status and missing elements
    """
    if not isinstance(device_requirements, dict):
        raise ValueError(
            f"device_requirements must be a dict, got {type(device_requirements)}"
        )

    if not isinstance(endpoint, dict):
        raise ValueError(f"endpoint must be a dict, got {type(endpoint)}")

    result = {
        "device_type_id": device_type_id,
        "device_type_name": device_requirements.get("name", "unknown"),
        "is_compliant": True,
        "missing_elements": [],
        "duplicate_elements": [],
        "cluster_validations": [],
        "revision_issues": [],
        "event_warnings": [],
    }

    required_clusters = device_requirements.get("clusters", [])
    endpoint_clusters = endpoint.get("clusters", {})

    required_device_revision = device_requirements.get("revision")

    descriptor_cluster = endpoint_clusters.get(DESCRIPTOR_CLUSTER_ID, {})
    device_type_list = None
    actual_device_revision = None

    descriptor_attrs = descriptor_cluster.get("attributes", {})
    device_type_list = descriptor_attrs.get(DEVICE_TYPE_LIST_ATTRIBUTE_ID, {}).get(
        "DeviceTypeList", []
    )

    device_type_hex = convert_to_hex(device_type_id)
    if device_type_list:
        for device_type_info in device_type_list:
            if isinstance(device_type_info, dict):
                device_type = device_type_info.get("DeviceType")
                if device_type is not None:
                    if isinstance(device_type, dict):
                        actual_device_id = convert_to_hex(device_type.get("id"))
                        if actual_device_id == device_type_hex:
                            actual_device_revision = device_type_info.get("Revision")
                            break
                    elif isinstance(device_type, (int, str)):
                        actual_device_id = convert_to_hex(device_type)
                        if actual_device_id == device_type_hex:
                            actual_device_revision = device_type_info.get("Revision")
                            break

    if actual_device_revision is not None and required_device_revision is not None:
        device_type_name = device_requirements.get("name")
        if not device_type_name:
            logger.error(f"Device type {device_type_hex} has no name, skipping")
            return result

        revision_compliant, revision_issues = validate_revisions(
            actual_device_revision,
            required_device_revision,
            "device_type",
            device_type_hex,
            device_type_name,
        )
        if not revision_compliant:
            result["is_compliant"] = False
        result["revision_issues"].extend(revision_issues)
    else:
        logger.error(f"Device type revision not found for {device_type_hex}")
        result["is_compliant"] = False
        result["revision_issues"].append(
            {
                "type": "revision_error",
                "message": f"Device type revision not found for {device_type_hex}",
            }
        )
        return result

    for required_cluster in required_clusters:
        if not isinstance(required_cluster, dict):
            logger.error(
                f"Cluster {required_cluster.get('id')} is not a dict, skipping"
            )
            return result

        cluster_name = required_cluster.get("name")
        if not cluster_name:
            logger.error(f"Cluster {required_cluster.get('id')} has no name, skipping")
            return result

        try:
            cluster_validation = validate_cluster(endpoint_clusters, required_cluster)
            result["cluster_validations"].append(cluster_validation)

            if not cluster_validation["is_compliant"]:
                result["is_compliant"] = False
                result["missing_elements"].extend(
                    cluster_validation["missing_elements"]
                )

            if "duplicate_elements" in cluster_validation:
                result["duplicate_elements"].extend(
                    cluster_validation["duplicate_elements"]
                )

            if "revision_issues" in cluster_validation:
                result["revision_issues"].extend(cluster_validation["revision_issues"])

            if "event_warnings" in cluster_validation:
                result["event_warnings"].extend(cluster_validation["event_warnings"])

        except Exception as cluster_error:
            raise Exception(
                f"Error validating cluster {cluster_name}: {cluster_error}"
            ) from cluster_error

    return result


def validate_device_conformance(
    parsed_data: dict,
    spec_version: str
) -> dict:
    """Validate if the device meets all requirements for its device types.

    Args:
        parsed_data: The parsed device data from wildcard logs containing endpoints and clusters
        spec_version: The Matter specification version

    Returns:
        Validation results with conformance status and missing elements
    """
    logger.debug("Starting device conformance validation...")

    validation_data = load_chip_validation_data(spec_version)
    if not validation_data:
        error_msg = f"No validation data JSON found for spec version {spec_version}"
        raise ValueError(error_msg)

    if not isinstance(parsed_data, dict):
        raise ValueError("parsed_data must be a dictionary")

    if "endpoints" not in parsed_data:
        raise ValueError("parsed_data must contain 'endpoints' key")

    validation_results = {
        "endpoints": [],
        "summary": {
            "total_endpoints": 0,
            "compliant_endpoints": 0,
            "non_compliant_endpoints": 0,
            "total_revision_issues": 0,
            "total_event_warnings": 0,
            "total_duplicate_elements": 0,
        },
    }

    try:
        # id: device_data mapping for fast lookup
        requirements_lookup = {}
        for i, device in enumerate(validation_data):
            if not isinstance(device, dict):
                logger.error(f"Device {device} is not a dict, skipping")
                continue

            device_id = device.get("id")
            if device_id:
                device_id_int = convert_to_int(device_id)
                if device_id_int is not None:
                    requirements_lookup[device_id_int] = device

        endpoints_list = parsed_data.get("endpoints", [])
        total_endpoints = len(endpoints_list)

        total_revision_issues = 0
        total_event_warnings = 0

        for i, endpoint in enumerate(endpoints_list):
            endpoint_result = {
                "endpoint": endpoint["id"],
                "device_types": [],
                "is_compliant": True,
                "missing_elements": [],
                "duplicate_elements": [],
                "extra_elements": [],
                "revision_issues": [],
                "event_warnings": [],
            }

            descriptor_cluster = endpoint.get("clusters", {}).get(
                DESCRIPTOR_CLUSTER_ID, {}
            )
            device_type_list = None

            descriptor_attrs = descriptor_cluster.get("attributes", {})
            device_type_list = descriptor_attrs.get(
                DEVICE_TYPE_LIST_ATTRIBUTE_ID, {}
            ).get("DeviceTypeList", [])

            if not device_type_list:
                endpoint_result["device_types"].append(
                    {"error": "No DeviceTypeList found in descriptor cluster"}
                )
                endpoint_result["is_compliant"] = False
            else:
                for device_type_index, device_type_info in enumerate(device_type_list):
                    if isinstance(device_type_info, dict):
                        device_type_id = device_type_info.get("DeviceType")
                        if isinstance(device_type_id, dict):
                            device_type_id = device_type_id.get(
                                "id"
                            ) or device_type_id.get("DeviceType")
                    elif isinstance(device_type_info, (int, str)):
                        device_type_id = device_type_info
                    else:
                        endpoint_result["device_types"].append(
                            {
                                "error": f"Unexpected device type format: {type(device_type_info)} - {device_type_info}"
                            }
                        )
                        endpoint_result["is_compliant"] = False
                        continue

                    device_type_id_int = convert_to_int(device_type_id)
                    if device_type_id_int is None:
                        endpoint_result["device_types"].append(
                            {
                                "error": f"Invalid device type ID format: {type(device_type_id)} - {device_type_id}"
                            }
                        )
                        endpoint_result["is_compliant"] = False
                        continue

                    if device_type_id_int in requirements_lookup:
                        device_requirements = requirements_lookup[device_type_id_int]

                        logger.debug(f"Validating device type {device_type_id_int}")

                        device_validation = validate_single_device_type(
                            endpoint, device_type_id_int, device_requirements
                        )

                        endpoint_result["device_types"].append(device_validation)

                        if not device_validation["is_compliant"]:
                            logger.debug(
                                f"Device type {device_type_id_int} is not compliant"
                            )
                            logger.debug(
                                f"Missing elements: {device_validation.get('missing_elements', [])}"
                            )
                            endpoint_result["is_compliant"] = False

                        endpoint_result["missing_elements"].extend(
                            device_validation.get("missing_elements", [])
                        )

                        endpoint_result["duplicate_elements"].extend(
                            device_validation.get("duplicate_elements", [])
                        )

                        endpoint_result["revision_issues"].extend(
                            device_validation.get("revision_issues", [])
                        )

                        endpoint_result["event_warnings"].extend(
                            device_validation.get("event_warnings", [])
                        )

                    else:
                        # Unknown device type - likely vendor-specific
                        # Log warning and continue instead of crashing
                        device_type_hex = f"0x{device_type_id_int:08X}"
                        is_vendor_specific = device_type_id_int >= 0xFFF00000

                        if is_vendor_specific:
                            logger.warning(
                                f"Skipping vendor-specific device type {device_type_hex} "
                                f"(no validation requirements available)"
                            )
                            endpoint_result["device_types"].append({
                                "device_type_id": device_type_hex,
                                "device_type_name": "vendor_specific",
                                "is_compliant": True,  # Can't validate, assume compliant
                                "skipped": True,
                                "reason": "Vendor-specific device type - no requirements in spec"
                            })
                        else:
                            logger.warning(
                                f"Unknown device type {device_type_hex} not found in "
                                f"Matter specification requirements"
                            )
                            endpoint_result["device_types"].append({
                                "device_type_id": device_type_hex,
                                "device_type_name": "unknown",
                                "is_compliant": False,
                                "skipped": True,
                                "reason": f"Device type {device_type_hex} not found in spec"
                            })
                            endpoint_result["is_compliant"] = False

            validation_results["endpoints"].append(endpoint_result)

        compliant_endpoints = sum(
            1 for ep in validation_results["endpoints"] if ep["is_compliant"]
        )
        non_compliant_endpoints = total_endpoints - compliant_endpoints

        total_duplicate_elements = sum(
            len(ep.get("duplicate_elements", []))
            for ep in validation_results["endpoints"]
        )
        total_revision_issues = sum(
            len(ep.get("revision_issues", [])) for ep in validation_results["endpoints"]
        )
        total_event_warnings = sum(
            len(ep.get("event_warnings", [])) for ep in validation_results["endpoints"]
        )

        validation_results["summary"].update(
            {
                "total_endpoints": total_endpoints,
                "compliant_endpoints": compliant_endpoints,
                "non_compliant_endpoints": non_compliant_endpoints,
                "total_revision_issues": total_revision_issues,
                "total_event_warnings": total_event_warnings,
                "total_duplicate_elements": total_duplicate_elements,
            }
        )

        return validation_results

    except Exception as e:
        raise ValueError(f"Error processing device requirements: {e}") from e


def validate_data_model_conformance(file_path, spec_version, output_path):
    """Validate Matter device data model conformance from chip-tool wildcard logs.

    Args:
        file_path: Path to the chip-tool wildcard log file to analyze
        spec_version: Matter specification version
        output_path: Output path for the conformance report
    """
    try:
        logger.info(f"Reading wildcard log file: {file_path}")
        with open(file_path, "r") as file:
            data = file.read()

        logger.info("Parsing wildcard log data...")
        parsed_data = parse_datamodel_logs(data)

        if spec_version is None:
            logger.debug("Auto-detecting Matter specification version...")
            spec_version = detect_spec_version_from_parsed_data(parsed_data)
            if spec_version:
                logger.info(f"Auto-detected version: {spec_version}")

        logger.debug(f"Loading validation data json for version: {spec_version}")

        logger.info("Validating device conformance...")
        validation_results = validate_device_conformance(parsed_data, spec_version)

        logger.info("Generating conformance report...")
        report_text = generate_conformance_report(validation_results, spec_version)

        if output_path is None:
            output_path = os.path.join(
                os.getcwd(), DEFAULT_OUTPUT_DIR, DEFAULT_REPORT_FILE
            )

        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as file:
            file.write(report_text)

        summary = validation_results.get("summary", {})
        total_endpoints = summary.get("total_endpoints", 0)
        compliant_endpoints = summary.get("compliant_endpoints", 0)
        logger.info(
            f"Conformance Rate: {compliant_endpoints}/{total_endpoints} endpoints"
        )
        logger.info(f"Full report saved to: {output_path}")

        return compliant_endpoints == total_endpoints

    except Exception as e:
        raise ValueError(f"Validation error: {str(e)}") from e
