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
import xml.etree.ElementTree as ET

from dmv_tool.generators.helpers import (
    check_valid_id,
    safe_get_attr,
    convert_to_snake_case,
)
from dmv_tool.configs.constants import CPP_RESERVED_WORDS
from dmv_tool.generators.elements import (
    Cluster,
    Attribute,
    Command,
    Event,
    Feature,
    Device,
)
from dmv_tool.generators.conformance import (
    parse_conformance,
    parse_otherwise_conformance,
    check_conformance_restrictions,
    match_conformance_items,
)
from typing import List

logger = logging.getLogger(__name__)


class DatamodelParser:

    def __init__(self):
        pass

    class ClusterParser:
        """Class for parsing cluster data"""

        def __init__(self):
            self.datamodel = DatamodelParser()

        def parse(self, file_path: str, base_clusters: List[Cluster] = None):
            """Parses an XML cluster file
            (A single base cluster file can have multiple derived clusters in single file)

            Args:
                file_path: The path to the cluster XML file.
                base_clusters: A list of base clusters.

            Returns:
                A list of clusters.
            """
            tree = ET.parse(file_path)
            root = tree.getroot()

            clusters = []

            cluster_revision = root.get("revision")

            cluster_name_id_list = self._get_cluster_name_and_id(root)
            if not cluster_name_id_list or len(cluster_name_id_list) == 0:
                logger.error(f"Skipping {file_path} as it is not a valid cluster")
                return clusters

            for cluster_name, cluster_id in cluster_name_id_list:
                if not cluster_name or not cluster_id:
                    logger.warning(
                        f"Skipping {file_path} as name or id is missing, (Either base cluster or not supported yet)"
                    )
                    continue
                if not check_valid_id(cluster_id):
                    logger.warning(
                        f"Skipping {file_path} as id is not valid: {cluster_id}"
                    )
                    continue

                base_cluster = None
                if base_clusters:
                    base_cluster = self._get_base_cluster(root, base_clusters)
                cluster = self._parse_cluster(
                    root,
                    cluster_name,
                    cluster_id,
                    cluster_revision,
                    base_cluster,
                )
                clusters.append(cluster)
            return clusters

        def _parse_cluster(
            self,
            root,
            cluster_name,
            cluster_id,
            cluster_revision,
            base_cluster: Cluster = None,
        ):
            """Parse a cluster from XML

            Args:
                root: The root element of the cluster XML file.
                cluster_name: The name of the cluster.
                cluster_id: The ID of the cluster.
                cluster_revision: The revision of the cluster.
                base_cluster: A base cluster.

            Returns:
                The parsed cluster.

            """
            cluster = Cluster(
                id=cluster_id, name=cluster_name, revision=cluster_revision
            )
            classification = root.find("classification")
            if classification is not None:
                cluster.role = classification.get("role", "application")
                cluster.hierarchy = classification.get("hierarchy")
                base_cluster_name = classification.get("baseCluster")
                if base_cluster_name:
                    cluster.base_cluster_name = convert_to_snake_case(base_cluster_name)
                cluster.pics_code = classification.get("picsCode")
                cluster.scope = classification.get("scope")
            else:
                logger.debug(
                    f"Classification element not found for cluster {cluster_name}, using default role 'application'"
                )
                cluster.role = "application"

            feature_parser = self.datamodel.FeatureParser(root, cluster, self.datamodel)
            feature_map = feature_parser.create_feature_map()
            feature_parser.feature_map = feature_map

            attribute_parser = self.datamodel.AttributeParser(
                cluster, feature_parser.feature_map, self.datamodel
            )
            command_parser = self.datamodel.CommandParser(
                cluster, feature_parser.feature_map, self.datamodel
            )
            event_parser = self.datamodel.EventParser(
                cluster, feature_parser.feature_map, self.datamodel
            )

            base_attributes = base_cluster.attributes if base_cluster else []
            base_commands = base_cluster.commands if base_cluster else []
            base_events = base_cluster.events if base_cluster else []
            base_features = base_cluster.features if base_cluster else []
            attribute_parser.parse(root, base_attributes)
            command_parser.parse(root, base_commands)
            event_parser.parse(root, base_events)
            feature_parser.compute_features(feature_parser.feature_map, base_features)
            return cluster

        def _get_cluster_name_and_id(self, root):
            """Get cluster name and id from XML

            Args:
                root: The root element of the cluster XML file.

            Returns:
                A list of cluster name and id.
            """
            name_id_list = []
            cluster_name = root.get("name").replace(" Cluster", "")
            cluster_id = root.get("id")

            name_id_list.append([cluster_name, cluster_id])
            if cluster_name and cluster_id:
                return name_id_list

            if not cluster_name or not cluster_id:
                cluster_ids_element = root.find("clusterIds").findall("clusterId")
                for cluster_id_element in cluster_ids_element:
                    cluster_name = cluster_id_element.get("name")
                    cluster_id = cluster_id_element.get("id")
                    if not cluster_id:
                        # Default to 0xFFFF if id is not present
                        cluster_id = hex(0xFFFF)
                    if cluster_name and cluster_id:
                        name_id_list.append([cluster_name, cluster_id])

            return name_id_list

        def _get_base_cluster(self, root, base_clusters: List[Cluster]):
            """Get base cluster from root

            Args:
                root: The root element of the cluster XML file.
                base_clusters: The base cluster list.

            Returns:
                The base cluster.
            """
            base_cluster = None
            base_cluster_name = root.find("classification").get("baseCluster")
            if base_cluster_name:
                base_cluster = next(
                    (
                        bc
                        for bc in base_clusters
                        if convert_to_snake_case(bc.name)
                        == convert_to_snake_case(base_cluster_name)
                    ),
                    None,
                )
            return base_cluster

    class AttributeParser:
        """Class for parsing attribute data"""

        def __init__(self, cluster: Cluster, feature_map: dict, datamodel):
            """Initialize the AttributeParser"""
            self.cluster = cluster
            self.feature_map = feature_map if feature_map else {}
            self.processed_attrs = set()
            self.datamodel = datamodel

        def parse(self, root, base_attributes: List[Attribute] = None):
            """Iterate over all attributes in the cluster and create Attribute objects.

            Args:
                root: The root element of the cluster XML file.
                base_attributes: The list of base attributes from base cluster.

            Returns:
                None
            """
            for attribute in root.findall("attributes/attribute"):
                attribute_name = attribute.get("name")
                if not self.datamodel.should_process_element(
                    attribute,
                    attribute_name,
                    "attribute",
                    self.processed_attrs,
                    self.feature_map,
                    base_attributes,
                ):
                    continue
                attr = self.datamodel.create_element(attribute, "attribute")
                self.datamodel.process_element_conformance(
                    attr, attribute, self.feature_map
                )

                self.cluster.attributes.add(attr)

            if base_attributes:
                for base_attribute in base_attributes:
                    if convert_to_snake_case(base_attribute.name) not in [
                        convert_to_snake_case(name) for name in self.processed_attrs
                    ]:
                        self.cluster.attributes.add(base_attribute)

            logger.debug(
                f"Processed {len(self.cluster.attributes)} attributes for cluster {safe_get_attr(self.cluster, 'name')}"
            )

    class CommandParser:
        """Class for parsing command data"""

        def __init__(
            self,
            cluster: Cluster,
            feature_map: dict,
            datamodel,
        ):
            self.cluster = cluster
            self.feature_map = feature_map if feature_map else {}
            self.processed_commands = set()
            self.datamodel = datamodel

        def parse(self, root, base_commands: List[Command] = None):
            """Iterate over all command elements in the cluster xml file and create Command objects.

            Args:
                root: The root element of the cluster XML file.
                base_commands: The list of base commands from base cluster.

            Returns:
                None

            """
            for command in root.findall("commands/command"):
                command_name = command.get("name")
                if not self.datamodel.should_process_element(
                    command,
                    command_name,
                    "command",
                    self.processed_commands,
                    self.feature_map,
                    base_commands,
                ):
                    continue

                cmd = self.datamodel.create_element(command, "command")
                self.datamodel.process_element_conformance(
                    cmd, command, self.feature_map
                )
                self.cluster.commands.add(cmd)

            if base_commands:
                for base_command in base_commands:
                    if convert_to_snake_case(base_command.name) not in [
                        convert_to_snake_case(name) for name in self.processed_commands
                    ]:
                        self.cluster.commands.add(base_command)

            logger.debug(
                f"Processed {len(self.cluster.commands)} commands for cluster {safe_get_attr(self.cluster, 'name')}"
            )

    class EventParser:
        """Class for parsing event data"""

        def __init__(self, cluster, feature_map, datamodel):
            self.cluster = cluster
            self.feature_map = feature_map if feature_map else {}
            self.processed_events = set()
            self.datamodel = datamodel

        def parse(self, root, base_events: List[Event] = None):
            """Iterate over all events in the cluster and create Event objects.

            Args:
                root: The root element of the cluster XML file.
                base_events: The list of base events from base cluster.

            Returns:
                None

            """
            for event in root.findall("events/event"):
                event_name = event.get("name")
                if not self.datamodel.should_process_element(
                    event,
                    event_name,
                    "event",
                    self.processed_events,
                    self.feature_map,
                    base_events,
                ):
                    continue
                evt = self.datamodel.create_element(event, "event")
                self.datamodel.process_element_conformance(evt, event, self.feature_map)
                self.cluster.events.add(evt)

            if base_events:
                for base_event in base_events:
                    if convert_to_snake_case(base_event.name) not in [
                        convert_to_snake_case(name) for name in self.processed_events
                    ]:
                        self.cluster.events.add(base_event)

            logger.debug(
                f"Processed {len(self.cluster.events)} events for cluster {safe_get_attr(self.cluster, 'name')}"
            )

    class FeatureParser:
        """ """

        def __init__(self, root, cluster, datamodel):
            self.root = root
            self.cluster = cluster
            self.feature_map = {}
            self.processed_features = set()
            self.datamodel = datamodel

        def create_feature_map(self):
            """Create a map of features from XML. e.g. {"LT": <lighting_feature_obj>}

            Args:
                root: The root element of the cluster XML file.

            Returns:
                A map of features.

            :returns: A map of features.

            """
            features_elem = self.root.find("features")
            if features_elem is None:
                logger.debug(f"No features found for cluster {self.cluster.name}")
                return self.feature_map

            feature_codes = self._collect_features()

            for feature_elem in features_elem.findall("feature"):
                feature = self._create_basic_feature(feature_elem, feature_codes)
                if feature:
                    self.feature_map[feature.code] = feature
            return self.feature_map

        def _collect_features(self) -> List[str]:
            """Collect features from XML. e.g. ["LT", "AC"]


            Returns:
                A list of features.

            """
            features_elem = self.root.find("features")
            if features_elem is None:
                return []
            features = []
            for feature_elem in features_elem.findall("feature"):
                features.append(feature_elem.get("code"))
            return features

        def _create_basic_feature(self, feature_elem, feature_codes: List[str]):
            """Create a basic Feature object from XML element without conformance

            Args:
                feature_elem: The feature element from the cluster XML file.
                feature_codes: A list of all feature codes in the cluster.

            Returns:
                The created Feature object.

            """
            feature_name = feature_elem.get("name")
            if feature_name in self.processed_features:
                logger.debug(f"Skipping {feature_name} as it is already processed")
                return None
            # Passing feature_map as None because we assume that feature-map is not created yet
            if check_conformance_restrictions(None, feature_elem):
                logger.debug(
                    f"Skipping feature {feature_name} due to conformance restrictions"
                )
                return None
            self.processed_features.add(feature_name)
            feature_code = feature_elem.get("code")
            feature_summary = feature_elem.get("summary")
            feature_bit = feature_elem.get("bit")
            if not (feature_name and feature_code):
                logger.warning(
                    f"Skipping feature due to missing required attributes feature_name: {feature_name} feature_code: {feature_code}"
                )
                return None

            feature_obj = Feature(
                name=(
                    feature_name
                    if feature_name is not None
                    and feature_name.lower() not in CPP_RESERVED_WORDS
                    else self.cluster.convert_to_snake_case + "_" + feature_name
                ),
                code=feature_code,
                id=self._compute_feature_id(int(feature_bit)),
            )

            if feature_summary:
                feature_obj.summary = feature_summary

            return feature_obj

        def _compute_feature_id(self, feature_bit):
            """Compute the feature id based on the number of existing features. e.g. feature_bit = 0x1, feature_id = 0x1 << 0x1 = 0x2, feature_bit = 0x2, feature_id = 0x1 << 0x2 = 0x4 etc.

            Args:
                feature_bit: The bit value of the feature.

            Returns:
                The computed feature id.
            """
            feature_id = 0x1 << feature_bit
            return feature_id

        def compute_features(self, feature_map, base_features: List[Feature] = None):
            """Add feature data to cluster

            Args:
                feature_map: The feature map.
                base_features: The list of base features from base cluster.

            Returns:
                None
            """
            for feature_obj in feature_map.values():
                self._process_feature(feature_obj, base_features)
                self.cluster.features.add(feature_obj)

            if base_features:
                for base_feature in base_features:
                    if base_feature.code not in self.feature_map.keys():
                        self.cluster.features.add(base_feature)

        def _process_feature(self, feature_obj, base_features: List[Feature] = None):
            """This will create a list of attributes, commands and events those having conformance with the given feature.

            Args:
                feature_obj: The feature object to process.
                base_features: The list of base features from base cluster.

            Returns:
                None
            """
            feature_attribute_list = match_conformance_items(
                feature_obj, self.cluster.get_attribute_list()
            )
            if feature_attribute_list:
                feature_obj.add_attribute_list(feature_attribute_list)

            feature_command_list = match_conformance_items(
                feature_obj, self.cluster.get_command_list()
            )

            if feature_command_list:
                feature_obj.add_command_list(feature_command_list)

            feature_event_list = match_conformance_items(
                feature_obj, self.cluster.get_event_list()
            )
            if feature_event_list:
                feature_obj.add_event_list(feature_event_list)

    class DeviceParser:
        """Class for parsing device data"""

        def __init__(self):
            self.datamodel = DatamodelParser()

        def parse(self, file_path):
            """Parse a device XML file and return the parsed device object.

            Args:
                file_path: The path to the device XML file.

            Returns:
                The parsed device object.

            """
            tree = ET.parse(file_path)
            root = tree.getroot()

            device_name, device_id = self._get_name_and_id(root)
            if not check_valid_id(device_id):
                logger.error(
                    f"Skipping {file_path} as device id is not valid: {device_id}"
                )
                return None
            device_revision = root.get("revision")

            # Passing feature_map as None because in case of device feature_map is not available
            if not self.datamodel.should_process_element(
                root, device_name, "device", set(), None, None
            ):
                logger.error(
                    f"Skipping {file_path} as device is not valid for processing: {device_name}"
                )
                return None

            device = Device(id=device_id, name=device_name, revision=device_revision)

            self._parse_revision_history(device, root)
            self._parse_classification(device, root)
            self._parse_conditions(device, root)

            self._parse_clusters(device, root, file_path)
            return device

        def _parse_clusters(self, device, root, file_path):
            """Parse the clusters from the device XML file.

            Args:
                device: The device object to add the clusters to.
                root: The root element of the device XML file.
                file_path: The path to the device XML file.

            Returns:
                None
            """
            clusters_element = root.find("clusters")
            if clusters_element is not None:
                for cluster in clusters_element.findall("cluster"):
                    cluster_id = cluster.get("id")
                    if not check_valid_id(cluster_id):
                        logger.warning(
                            f"Skipping {file_path} as cluster id is not valid: {cluster_id}"
                        )
                        continue
                    cluster_name = cluster.get("name")
                    cluster_side = cluster.get("side")
                    cluster_info = Cluster(name=cluster_name, id=cluster_id, revision=0)

                    if cluster_side == "server":
                        cluster_info.server_cluster = True
                    elif cluster_side == "client":
                        cluster_info.client_cluster = True

                    mandatory_conform = cluster.find("mandatoryConform")
                    if mandatory_conform is not None:
                        if (
                            mandatory_conform.find("condition") is None
                            and len(mandatory_conform) == 0
                        ):
                            cluster_info.is_mandatory = True
                        else:
                            cluster_info.mandatory_with_condition = True
                    else:
                        cluster_info.is_mandatory = False

                    cluster_info.feature_name_list = self._gen_cluster_element_lists(
                        cluster, "features", "feature"
                    )
                    cluster_info.command_name_list = self._gen_cluster_element_lists(
                        cluster, "commands", "command"
                    )
                    cluster_info.event_name_list = self._gen_cluster_element_lists(
                        cluster, "events", "event"
                    )
                    cluster_info.attribute_name_list = self._gen_cluster_element_lists(
                        cluster, "attributes", "attribute"
                    )

                    device.clusters.add(cluster_info)

        def _gen_cluster_element_lists(
            self, cluster_element, element_root_tag, element_type
        ):
            """Generate a list of elements from the cluster XML file."""
            item_list = []
            item_type = cluster_element.find(element_root_tag)
            if item_type is None:
                return item_list
            for element in item_type.findall(element_type):
                is_mandatory = False
                mandatory_conform = element.find("mandatoryConform")
                if mandatory_conform is not None and len(mandatory_conform) == 0:
                    is_mandatory = True
                element_id = (
                    element.get("id") if element.get("id") else element.get("code")
                )
                item_list.append(
                    {
                        "id": element_id,
                        "name": convert_to_snake_case(element.get("name")),
                        "is_mandatory": is_mandatory,
                    }
                )
            return item_list

        def _parse_revision_history(self, device, root):
            """Parse the revision history from the device XML file.

            Args:
                device: The device object to add the revision history to.
                root: The root element of the device XML file.

            Returns:
                None
            """
            revision_history_elem = root.find("revisionHistory")
            if revision_history_elem is not None:
                device.revision_history = []
                for revision in revision_history_elem.findall("revision"):
                    revision_info = {
                        "revision": revision.get("revision"),
                        "summary": revision.get("summary"),
                    }
                    device.revision_history.append(revision_info)

        def _parse_classification(self, device, root):
            """Parse the classification from the device XML file.

            Args:
                device: The device object to add the classification to.
                root: The root element of the device XML file.

            Returns:
                None
            """
            classification_elem = root.find("classification")
            if classification_elem is not None:
                for attr_name, attr_value in classification_elem.attrib.items():
                    device.classification[attr_name] = attr_value

        def _parse_conditions(self, device, root):
            """Parse the conditions from the device XML file.

            Args:
                device: The device object to add the conditions to.
                root: The root element of the device XML file.

            Returns:
                None
            """
            conditions_elem = root.find("conditions")
            if conditions_elem is not None:
                device.conditions = []
                for condition in conditions_elem.findall("condition"):
                    condition_info = {
                        "name": condition.get("name"),
                        "summary": condition.get("summary"),
                    }
                    device.conditions.append(condition_info)

        def _get_name_and_id(self, root):
            """Get the name and id of the device.

            Args:
                root: The root element of the device XML file.

            Returns:
                A tuple containing the name and id of the device.

            """
            name = root.get("name")
            id = root.get("id")
            return name, id

    def process_element_conformance(self, element, xml_element, feature_map):
        """Process attribute conformance information from XML

        Args:
            element: The element object to process.
            xml_element: The element element from the cluster XML file.
            feature_map: The feature map.

        Returns:
            None

        """
        mandatory_conform = xml_element.find("mandatoryConform")
        optional_conform = xml_element.find("optionalConform")
        otherwise_conform = xml_element.find("otherwiseConform")

        if mandatory_conform is not None:
            element.conformance = parse_conformance(mandatory_conform, feature_map)
        elif optional_conform is not None:
            element.conformance = parse_conformance(optional_conform, feature_map)
        elif otherwise_conform is not None:
            element.conformance = parse_otherwise_conformance(
                otherwise_conform, feature_map
            )

    def should_process_element(
        self,
        element,
        element_name,
        element_type,
        processed_set,
        feature_map,
        base_elements=None,
    ):
        """Generic method to check if an element should be processed

        Args:
            element: The XML element to check
            element_name: The name of the element
            element_type: The type of element (attribute, command, event)
            processed_set: Set of already processed element names
            feature_map: The feature: feature_obj dictionary
            base_elements: List of base elements from parent cluster

        Returns:
            True if the element should be processed, False otherwise
        """
        if element_name in processed_set:
            return False
        processed_set.add(element_name)

        if base_elements:
            base_element = next(
                (elem for elem in base_elements if elem.name == element_name), None
            )
            if not element.get("id") and base_element:
                element.set("id", base_element.id)

        element_id = element.get("id")
        if not check_valid_id(element_id):
            return False
        if not (element_name and element_id):
            logger.debug(
                f"Skipping - missing name or id for {element_type} {element_name} {element_id}"
            )
            return False

        if check_conformance_restrictions(feature_map, element):
            logger.debug(
                f"Skipping - {element_type} {element_name} due to conformance restrictions"
            )
            return False

        return True

    def create_element(self, xml_element, element_type, **kwargs):
        """Generic element factory method

        Args:
            xml_element: The XML element to create object from
            element_type: Type of element to create (attribute, command, event)
            **kwargs: Additional parameters specific to element type

        Returns:
            Created element object
        """
        element_name = xml_element.get("name")
        element_id = xml_element.get("id")

        mandatory_conform = xml_element.find("mandatoryConform")
        otherwise_conform = xml_element.find("otherwiseConform")
        if (
            otherwise_conform is not None
            and otherwise_conform.find("mandatoryConform") is not None
        ):
            mandatory_conform = otherwise_conform.find("mandatoryConform")

        is_mandatory = mandatory_conform is not None

        if element_type == "attribute":
            return Attribute(
                name=element_name,
                id=element_id,
                is_mandatory=is_mandatory,
            )
        elif element_type == "command":
            cmd = Command(
                id=element_id,
                name=element_name,
                direction=xml_element.get("direction"),
                response=xml_element.get("response"),
                is_mandatory=is_mandatory,
            )
            return cmd
        elif element_type == "event":
            return Event(
                id=element_id,
                name=element_name,
                is_mandatory=is_mandatory,
            )
        else:
            raise ValueError(f"Unknown element type: {element_type}")
