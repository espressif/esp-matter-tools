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

import os
import logging
import xml.etree.ElementTree as ET

from dmv_tool.generators.datamodel import DatamodelParser
from dmv_tool.generators.helpers import write_to_json_file

logger = logging.getLogger(__name__)


def get_base_and_derived_cluster_files(input_dir):
    """Get all base and derived cluster files from the input directory.

    Args:
        input_dir: Path to the directory containing the cluster XML files

    Returns:
        A tuple of (base_cluster_files, derived_cluster_files)
    """
    base_cluster_files = []
    derived_cluster_files = []

    file_list = os.listdir(input_dir)
    if file_list is None:
        logger.debug(f"No cluster XML files found in {input_dir}")
        return [], []

    for file_name in file_list:
        if file_name is not None and file_name.endswith(".xml"):
            file_path = os.path.join(input_dir, file_name)
            tree = ET.parse(file_path)
            root = tree.getroot()
            classification = root.find("classification")
            if (
                classification is not None
                and classification.get("hierarchy") == "derived"
            ):
                derived_cluster_files.append(file_path)
            else:
                base_cluster_files.append(file_path)
        else:
            logger.error(f"Skipping {file_name} as it is not a valid file")
            continue
    return base_cluster_files, derived_cluster_files


def process_cluster_files(
    input_dir,
    cluster_json_file,
):
    """Process all cluster XML files from input directory and generate cluster json file.

    Args:
        input_dir: Path to the directory containing the cluster XML files
        cluster_json_file: Path to the file where the cluster JSON will be written
    """
    try:
        base_cluster_xml_files, derived_cluster_xml_files = (
            get_base_and_derived_cluster_files(input_dir)
        )
        if len(base_cluster_xml_files) == 0 and len(derived_cluster_xml_files) == 0:
            raise Exception(f"No cluster XML files found in {input_dir}")

        cluster_parser = DatamodelParser().ClusterParser()
        base_clusters = []
        derived_clusters = []

        for file_path in base_cluster_xml_files:
            cluster_list = cluster_parser.parse(
                file_path=file_path,
            )

            if cluster_list is None or len(cluster_list) == 0:
                logger.error(f"Processing of {os.path.basename(file_path)} failed")
                continue

            base_clusters.extend(cluster_list)
            logger.debug(
                f"********************** Processing of {os.path.basename(file_path)} completed************************"
            )

        for file_path in derived_cluster_xml_files:
            cluster_list = cluster_parser.parse(
                file_path=file_path,
                base_clusters=base_clusters,
            )

            if cluster_list is None or len(cluster_list) == 0:
                logger.error(f"Processing of {os.path.basename(file_path)} failed")
                continue

            derived_clusters.extend(cluster_list)
            logger.debug(
                f"********************** Processing of {os.path.basename(file_path)} completed************************"
            )

        clusters = base_clusters + derived_clusters
        clusters_list = [cluster.to_dict() for cluster in clusters]
        clusters_list.sort(key=lambda x: int(x.get("id"), 16))

        write_to_json_file(cluster_json_file, clusters_list)

        logger.info(
            f"\n\n--------------------------------------------------PROCESSING COMPLETE | GENERATED cluster json in {cluster_json_file}--------------------------------------------------\n\n"
        )
    except Exception as e:
        raise Exception(f"Error processing cluster files: {str(e)}") from e


def process_device_files(input_dir, device_json_file):
    """Process all device XML files from input directory and generate intermediate device json file.

    Args:
        input_dir: Path to the directory containing the device XML files
        device_json_file: Path to the file where the device JSON will be written
    """
    try:
        file_list = os.listdir(input_dir)
        if file_list is None:
            raise Exception(f"No device XML files found in {input_dir}")

        devices = []
        device_parser = DatamodelParser().DeviceParser()
        for file_name in file_list:
            if file_name is not None and file_name.endswith(".xml"):
                file_path = os.path.join(input_dir, file_name)
                device = device_parser.parse(file_path)
                if device is None or device.name is None:
                    logger.error(f"Processing of {file_name} failed")
                    continue

                devices.append(device)
                logger.debug(
                    f"********************** Processing of {file_name} completed************************"
                )
            else:
                logger.error(f"Skipping {file_name} as it is not a valid file")
                continue

        devices_list = [device.to_dict() for device in devices]
        devices_list.sort(key=lambda x: int(x.get("id"), 16))
        write_to_json_file(device_json_file, devices_list)
        logger.info(
            f"\n\n--------------------------------------------------PROCESSING COMPLETE | GENERATED device json in {device_json_file}--------------------------------------------------\n\n"
        )
    except Exception as e:
        raise Exception(f"Error processing device files: {str(e)}") from e


def generate_json(chip_path, spec_version_dir, output_dir):
    """Generate JSON files for the given chip path and chip datamodel version.

    Args:
        chip_path: Path to the CHIP SDK root directory
        spec_version_dir: datamodel version directory name within CHIP SDK
        output_dir: Directory to write generated JSON files
    """
    try:
        assert chip_path is not None, "ConnectedHomeIP SDK path is not provided"

        os.makedirs(output_dir, exist_ok=True)

        # Intermediate json files.
        # Cluster files contains all the clusters with their attributes, commands, events, etc.
        # Device files contains all the device types with the clusters required for the device.
        cluster_json_file = os.path.join(output_dir, "clusters.json")
        device_json_file = os.path.join(output_dir, "device_types.json")

        xml_input_dir = os.path.join(chip_path, "data_model", spec_version_dir)
        cluster_input_dir = os.path.join(xml_input_dir, "clusters")
        device_input_dir = os.path.join(xml_input_dir, "device_types")

        logger.info(
            "************************************************* Processing device files *************************************************"
        )
        process_device_files(
            input_dir=device_input_dir, device_json_file=device_json_file
        )

        logger.info(
            "\n\n************************************************* Processing cluster files *************************************************"
        )
        process_cluster_files(
            input_dir=cluster_input_dir,
            cluster_json_file=cluster_json_file,
        )
    except Exception as e:
        raise Exception(f"Error generating JSON: {str(e)}") from e
