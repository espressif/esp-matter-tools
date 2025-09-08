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

from dmv_tool.generators.conformance import Conformance
from dmv_tool.generators.helpers import (
    safe_get_attr,
    convert_to_snake_case,
    modify_id,
)
from dmv_tool.configs.constants import CPP_RESERVED_WORDS
logger = logging.getLogger(__name__)


class BaseElement:
    """Base class for all elements."""

    def __init__(self, name, id):
        assert name, "Name is required"
        self.name = convert_to_snake_case(name)
        self.id = modify_id(id)
        self.convert_to_snake_case = convert_to_snake_case(name)
        self.func_name = convert_to_snake_case(name)

    def get_id(self):
        """Get the element ID.

        Returns:
            Element ID
        """
        return self.id


class BaseClusterElement(BaseElement):
    """Base class for cluster elements."""

    def __init__(self, name, id, is_mandatory):
        if name and name in CPP_RESERVED_WORDS or name.lower() in CPP_RESERVED_WORDS:
            name = name + "_Cluster"
        super().__init__(name=name, id=id)
        self.is_mandatory = is_mandatory


class Device(BaseElement):
    """Device class representing a Matter device type."""

    def __init__(self, id, name, revision):
        super().__init__(id=id, name=name)
        self.clusters = set()
        self.conformance = None
        self.revision = revision
        self.classification = {}

    def get_clusters(self):
        """Get all clusters sorted by ID and server type.

        Returns:
            Sorted list of clusters
        """
        return sorted(
            self.clusters, key=lambda x: (int(x.get_id(), 16), not x.server_cluster)
        )

    def get_mandatory_clusters(self):
        """Get mandatory clusters sorted by ID and server type.

        Returns:
            Sorted list of mandatory clusters
        """
        mandatory_clusters = []
        for cluster in self.clusters:
            if cluster.is_mandatory:
                mandatory_clusters.append(cluster)
        return sorted(
            mandatory_clusters,
            key=lambda x: (int(x.get_id(), 16), not x.server_cluster),
        )

    def get_all_mandatory_clusters(self):
        """Get all mandatory clusters including conditional ones.

        Returns:
            Sorted list of all mandatory clusters
        """
        mandatory_clusters_with_condition = []
        mandatory_clusters_with_condition.extend(self.get_mandatory_clusters())
        for cluster in self.clusters:
            if cluster.mandatory_with_condition:
                mandatory_clusters_with_condition.append(cluster)
        return sorted(
            mandatory_clusters_with_condition,
            key=lambda x: (int(x.get_id(), 16), not x.server_cluster),
        )

    def to_dict(self):
        """Convert device object to dictionary representation.

        Returns:
            Dictionary representation of device
        """
        from dmv_tool.generators.serializers import DeviceSerializer

        return DeviceSerializer.to_dict(self)


class Event(BaseClusterElement):
    """Event class representing a cluster event."""

    def __init__(self, id, name, is_mandatory):
        super().__init__(name, id, is_mandatory)
        self.conformance = None

    def is_plain_mandatory(self) -> bool:
        """Check if the event is just mandatory with any condition or feature dependency"""
        if (
            self.is_mandatory
            and safe_get_attr(self, "conformance") is not None
            and safe_get_attr(safe_get_attr(self, "conformance"), "condition") is None
        ):
            return True
        return False

    def to_dict(self, attribute_map=None):
        """Convert event object to dictionary representation.

        Args:
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Dictionary representation of event
        """
        from dmv_tool.generators.serializers import EventSerializer

        return EventSerializer.to_dict(self, attribute_map)


class Feature(BaseClusterElement):
    """Feature class representing a cluster feature."""

    def __init__(self, name, code, id):
        super().__init__(name, hex(id) if id is not None else None, is_mandatory=False)
        self.code = code
        self.command_set = set()
        self.attribute_set = set()
        self.event_set = set()
        self.conformance = None

    def get_attribute_list(self):
        """Get the list of mandatory attributes for this feature.

        Returns:
            Sorted list of attributes
        """
        attr_list = list(self.attribute_set)
        if len(attr_list) > 0:
            attr_list.sort(key=lambda x: int(x.get_id(), 16))
        return attr_list

    def get_event_list(self):
        """Get the list of mandatory events for this feature.

        Returns:
            Sorted list of events
        """
        event_list = list(self.event_set)
        if len(event_list) > 0:
            event_list.sort(key=lambda x: int(x.get_id(), 16))
        return event_list

    def get_command_list(self):
        """Get the list of mandatory commands for this feature.

        Returns:
            Sorted list of commands
        """
        command_list = list(self.command_set)
        if len(command_list) > 0:
            command_list.sort(key=lambda x: (int(x.get_id(), 16), x.name))
        return command_list

    def add_attribute_list(self, attribute_list):
        """Add a list of attributes to the feature."""
        self.attribute_set.update(attribute_list)

    def add_command_list(self, command_list):
        """Add a list of commands to the feature."""
        self.command_set.update(command_list)

    def add_event_list(self, event_list):
        """Add a list of events to the feature."""
        self.event_set.update(event_list)

    def to_dict(self, attribute_map=None):
        """Convert feature object to dictionary representation.

        Args:
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Dictionary representation of feature
        """
        from dmv_tool.generators.serializers import FeatureSerializer

        return FeatureSerializer.to_dict(self, attribute_map)


class Command(BaseClusterElement):
    """Command class representing a cluster command."""

    class CommandFlags:
        """Command flags enum."""

        COMMAND_FLAG_NONE = "COMMAND_FLAG_NONE"
        COMMAND_FLAG_CUSTOM = "COMMAND_FLAG_CUSTOM"
        COMMAND_FLAG_ACCEPTED = "COMMAND_FLAG_ACCEPTED"
        COMMAND_FLAG_GENERATED = "COMMAND_FLAG_GENERATED"

    def __init__(self, id, name, direction, response, is_mandatory):
        self.direction = direction
        self.response = response
        super().__init__(
            (
                name.split(" ")[0]
                if len(name.split(" ")) > 1 and name.split(" ")[1] == "Command"
                else name
            ),
            id,
            is_mandatory,
        )

    def get_flag(self):
        """_summary_

        Returns:
            _type_: _description_
        """ """Get the command flag based on direction.

        Returns:
            Command flag string
        """
        if self.direction and self.direction.lower() == "commandtoserver":
            return self.CommandFlags.COMMAND_FLAG_ACCEPTED
        elif self.direction and self.direction.lower() == "responsefromserver":
            return self.CommandFlags.COMMAND_FLAG_GENERATED
        return self.CommandFlags.COMMAND_FLAG_NONE

    def is_plain_mandatory(self) -> bool:
        """Check if the command is just mandatory with any condition or feature dependency"""
        if (
            self.is_mandatory
            and safe_get_attr(self, "conformance") is not None
            and safe_get_attr(safe_get_attr(self, "conformance"), "condition") is None
        ):
            return True
        return False

    def to_dict(self, attribute_map=None):
        """Convert command object to dictionary representation.

        Args:
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Dictionary representation of command
        """
        from dmv_tool.generators.serializers import CommandSerializer

        return CommandSerializer.to_dict(self, attribute_map)


class Attribute(BaseClusterElement):
    """Attribute class representing a cluster attribute."""

    def __init__(
        self,
        name,
        id,
        is_mandatory,
    ):
        super().__init__(name, id, is_mandatory)
        self.conformance: Conformance = None

    def is_plain_mandatory(self) -> bool:
        """Check if the attribute is just mandatory with any condition or feature dependency"""
        if (
            self.is_mandatory
            and safe_get_attr(self, "conformance") is not None
            and safe_get_attr(safe_get_attr(self, "conformance"), "condition") is None
        ):
            return True
        return False

    def to_dict(self, attribute_map=None):
        """Convert attribute object to dictionary representation.

        Args:
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Dictionary representation of attribute
        """
        from dmv_tool.generators.serializers import AttributeSerializer

        return AttributeSerializer.to_dict(self, attribute_map)


class Cluster(BaseClusterElement):
    """Cluster class representing a Matter cluster."""

    def __init__(self, name, id, revision):
        super().__init__(name, id, is_mandatory=False)
        self.revision = revision
        self.attributes: set[Attribute] = set()
        self.commands: set[Command] = set()
        self.events: set[Event] = set()
        self.features: set[Feature] = set()
        self.conformance: Conformance = None
        self.role = "application"  # Default value
        self.base_cluster_name = None
        self.mandatory_with_condition = False
        self.server_cluster = False
        self.client_cluster = False

    def get_revision(self):
        """Get the revision of the cluster.

        Returns:
            Cluster revision
        """
        return self.revision

    def get_attribute_list(self):
        """Get all attributes sorted by attribute id, then by name if ids match.

        Returns:
            Sorted list of mandatory attributes
        """
        cluster_attributes = list(self.attributes)
        cluster_attributes.sort(key=lambda x: (int(x.get_id(), 16), x.name))
        return cluster_attributes

    def get_command_list(self):
        """Get all commands sorted by command id, then by name if ids match.

        Returns:
            Sorted list of mandatory commands
        """
        cluster_commands = list(self.commands)
        cluster_commands.sort(key=lambda x: (int(x.get_id(), 16), x.name))
        return cluster_commands

    def get_event_list(self):
        """Get all events sorted by event id, then by name if ids match.

        Returns:
            Sorted list of events
        """
        cluster_events = list(self.events)
        cluster_events.sort(key=lambda x: (int(x.get_id(), 16), x.name))
        return cluster_events

    def get_feature_list(self):
        """Get all features sorted by feature id.

        Returns:
            Sorted list of features
        """
        cluster_features = list(self.features)
        cluster_features.sort(key=lambda x: int(x.get_id(), 16))
        return cluster_features

    def to_dict(self):
        """Convert cluster object to dictionary representation.

        Returns:
            Dictionary representation of cluster
        """
        from dmv_tool.generators.serializers import ClusterSerializer

        return ClusterSerializer.to_dict(self)
