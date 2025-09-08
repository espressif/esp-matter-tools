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
from typing import Any, Dict, List

from dmv_tool.generators.helpers import (
    load_json_file,
    write_to_json_file,
    convert_to_snake_case,
    clean_string,
)

logger = logging.getLogger(__name__)


def merge_items(device_items, cluster_items, merged_cluster, key):
    """
    Merge cluster items (commands/attributes) with device overrides.
    Keeps mandatory ones and those explicitly listed in device.
    """
    items_by_name = {item["name"]: dict(item) for item in cluster_items}

    required = {}
    for item in cluster_items:
        if item.get("mandatory"):
            required[item["name"]] = dict(item)

    for device_item in device_items:
        name = device_item.get("name", "")
        is_mandatory = device_item.get("is_mandatory", False)
        if name in items_by_name and is_mandatory:
            required[name] = dict(items_by_name[name])
        elif name in items_by_name and items_by_name[name].get("is_mandatory"):
            required[name] = dict(items_by_name[name])

    for item in required.values():
        item.pop("mandatory", None)

    merged_cluster[key] = sorted(
        required.values(),
        key=lambda x: (int(x.get("id", "0"), 16), x.get("name", "")),
    )


def create_cluster_lookup(clusters: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Create a lookup dictionary for clusters by ID.

    Args:
        clusters: List of cluster dictionaries

    Returns:
        A lookup dictionary for clusters by ID
    """
    cluster_lookup = {}
    for cluster in clusters:
        cluster_id = cluster.get("id")
        if cluster_id:
            cluster_lookup[cluster_id] = cluster
    return cluster_lookup


def convert_feature_name_to_code(
    feature_name: str, cluster_features: List[Dict[str, Any]]
) -> str:
    """Convert snake_case feature name to feature code.

    Args:
        feature_name: Feature name to convert
        cluster_features: List of cluster feature dictionaries

    Returns:
        The feature code e.g. LT for lighting
    """
    target_name = convert_to_snake_case(feature_name)

    for feature in cluster_features:
        if feature.get("name") == target_name or feature.get("code") == target_name:
            return feature.get("code", feature_name)

    return feature_name


def merge_device_cluster_with_full_definition(
    device_cluster: Dict[str, Any],
    full_cluster: Dict[str, Any],
    validation_data_json_file: str,
    output_dir: str,
) -> Dict[str, Any]:
    """Merge device-specific cluster info with full cluster definition.

    Args:
        device_cluster: Device cluster info from device_types.json
            (only required features, commands, events, attributes)
        full_cluster: Complete cluster info from clusters.json
            (all features, events, commands, attributes)

    Returns:
        A merged cluster dictionary
    """
    logger.debug(
        f"Merging device cluster { device_cluster.get('name', 'unknown')} with full cluster {full_cluster.get('name', 'unknown')}"
    )
    merged_cluster = full_cluster.copy()

    merged_cluster["type"] = device_cluster.get("type", "server")
    merged_cluster["required"] = device_cluster.get("required", False)

    device_features = device_cluster.get("features", [])
    full_features = full_cluster.get("features", [])

    device_feature_names = set()
    for feature in device_features:
        if feature.get("is_mandatory"):
            feature_name = feature.get("name", "")
            if feature_name is not None:
                device_feature_names.add(clean_string(feature_name).lower())
            else:
                device_feature_names.add(clean_string(feature.get("code", "")).lower())

    enhanced_features = []
    for feature in full_features:
        feature_copy = feature.copy()
        feature_name = feature.get("name", "")
        if feature_name is None:
            logger.warning(f"Feature name is None for feature: {feature}")
            continue

        cleaned_feature_name = clean_string(feature_name)
        cleaned_feature_code = clean_string(feature.get("code", ""))
        feature_copy["required"] = (
            cleaned_feature_name in device_feature_names
            or cleaned_feature_code in device_feature_names
        )
        enhanced_features.append(feature_copy)

    enhanced_features.sort(key=lambda x: (int(x.get("id", "0"), 16), x.get("name", "")))
    merged_cluster["features"] = enhanced_features

    merge_items(
        device_cluster.get("commands", []),
        full_cluster.get("commands", []),
        merged_cluster,
        "commands",
    )
    merge_items(
        device_cluster.get("attributes", []),
        full_cluster.get("attributes", []),
        merged_cluster,
        "attributes",
    )
    merge_items(
        device_cluster.get("events", []),
        full_cluster.get("events", []),
        merged_cluster,
        "events",
    )

    return merged_cluster


def combine_clusters_and_devices_json(
    clusters_file: str,
    device_types_file: str,
    validation_data_json_file: str,
    output_dir: str,
) -> Dict[str, Any]:
    """Combine clusters.json and device_types.json into single device with all the clusters requirements.

    Args:
        clusters_file: Path to the clusters.json file
        device_types_file: Path to the device_types.json file
        validation_data_json_file: Path to the validation_data.json file
        output_dir: Path to the output directory
    Returns:
        A list of device dictionaries with all the clusters requirements
    """
    try:
        logger.debug(
            f"Combining clusters and devices JSON: {clusters_file} "
            f"{device_types_file} {validation_data_json_file} {output_dir}"
        )
        clusters_data = load_json_file(clusters_file)
        device_types_data = load_json_file(device_types_file)

        if not clusters_data or not device_types_data:
            logger.debug(
                f"No clusters or device types data found in "
                f"{clusters_file} or {device_types_file}"
            )
            return {}

        cluster_lookup = create_cluster_lookup(clusters_data)

        complete_device_definitions = []

        for device in device_types_data:
            final_device = device.copy()
            complete_clusters = []

            for device_cluster in device.get("clusters", []):
                cluster_id = device_cluster.get("id")

                if cluster_id in cluster_lookup:
                    full_cluster = cluster_lookup[cluster_id]
                    merged_cluster = merge_device_cluster_with_full_definition(
                        device_cluster,
                        full_cluster,
                        validation_data_json_file,
                        output_dir,
                    )
                    complete_clusters.append(merged_cluster)
                else:
                    logger.warning(
                        f"Warning: Cluster {cluster_id} not found in clusters.json"
                    )
                    complete_clusters.append(device_cluster)

            final_device["clusters"] = complete_clusters
            complete_device_definitions.append(final_device)

        return complete_device_definitions
    except Exception as e:
        raise Exception(f"Error combining clusters and devices: {str(e)}") from e


def combine_clusters_devices_json(
    clusters_file: str,
    device_types_file: str,
    validation_data_json_file: str,
    output_dir: str,
) -> Dict[str, Any]:
    """Combine clusters.json and device_types.json to create enriched device definitions.

    Args:
        clusters_file: Path to the clusters.json file
        device_types_file: Path to the device_types.json file
        validation_data_json_file: Path to the validation_data.json file
        output_dir: Path to the output directory
    """
    complete_device_definitions = combine_clusters_and_devices_json(
        clusters_file, device_types_file, validation_data_json_file, output_dir
    )

    if not complete_device_definitions:
        raise Exception("Error: Failed to combine data")

    if not write_to_json_file(validation_data_json_file, complete_device_definitions):
        raise Exception(f"Failed to write combined data to {validation_data_json_file}")

    logger.debug(
        f"Successfully wrote complete device definitions to {validation_data_json_file}"
    )
