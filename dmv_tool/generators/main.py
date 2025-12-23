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

from dmv_tool.generators.core import (
    combine_clusters_devices_json,
)
from dmv_tool.generators.xml_parser import generate_json

logger = logging.getLogger(__name__)


def generate_chip_validation_data(
    chip_path,
    spec_version_dir,
    output_dir,
) -> bool:
    """Get the validation data for the given chip path and spec version.

    Args:
        chip_path: Path to the CHIP SDK root directory
        spec_version_dir: datamodel version directory name within CHIP SDK
        output_dir: Directory to write generated requirements json file
    """
    try:
        logger.info(
            f"Generating JSON files for {chip_path} and {spec_version_dir} in {output_dir}"
        )
        generate_json(chip_path, spec_version_dir, output_dir)
        logger.info(f"Generated JSON files in {output_dir}")
        clusters_json_file = os.path.join(output_dir, "clusters.json")
        device_types_json_file = os.path.join(output_dir, "device_types.json")
        validation_data_json_file = os.path.join(
            output_dir,
            f"validation_data_{spec_version_dir}.json",
        )
        combine_clusters_devices_json(
            clusters_json_file,
            device_types_json_file,
            validation_data_json_file,
            output_dir,
        )
        return True
    except Exception as e:
        raise Exception(
            f"Error generating validation data JSON from xml specifications: {str(e)}"
        ) from e
