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

"""
Serializer classes to convert source parser elements to dictionary representations.
This helps separate serialization logic from the data classes.
"""
from dmv_tool.generators.helpers import safe_get_attr


class AttributeSerializer:
    """Serializer for Attribute objects."""

    @staticmethod
    def to_dict(attr, serialize_mandatory=True):
        """Convert an Attribute object to dictionary representation.

        Args:
            attr: Attribute object to serialize

        Returns:
            Dictionary representation of attribute
        """
        if serialize_mandatory:
            return {
                "name": safe_get_attr(attr, "name"),
                "id": safe_get_attr(attr, "id"),
                "mandatory": attr.is_plain_mandatory(),
            }
        else:
            return {
                "name": safe_get_attr(attr, "name"),
                "id": safe_get_attr(attr, "id"),
            }


class CommandSerializer:
    """Serializer for Command objects."""

    @staticmethod
    def to_dict(cmd, serialize_mandatory=True):
        """Convert a Command object to dictionary representation.

        Args:
            cmd: Command object to serialize

        Returns:
            Dictionary representation of command
        """
        if serialize_mandatory:
            return {
                "name": safe_get_attr(cmd, "name"),
                "id": safe_get_attr(cmd, "id"),
                "mandatory": cmd.is_plain_mandatory(),
            }
        else:
            return {
                "name": safe_get_attr(cmd, "name"),
                "id": safe_get_attr(cmd, "id"),
            }


class EventSerializer:
    """Serializer for Event objects."""

    @staticmethod
    def to_dict(event, serialize_mandatory=True):
        """Convert an Event object to dictionary representation.

        Args:
            event: Event object to serialize

        Returns:
            Dictionary representation of event
        """
        if serialize_mandatory:
            return {
                "name": safe_get_attr(event, "name"),
                "id": event.get_id(),
                "mandatory": event.is_plain_mandatory(),
            }
        else:
            return {
                "name": safe_get_attr(event, "name"),
                "id": event.get_id(),
            }


class FeatureSerializer:
    """Serializer for Feature objects."""

    @staticmethod
    def to_dict(feature):
        """Convert a Feature object to dictionary representation.

        Args:
            feature: Feature object to serialize

        Returns:
            Dictionary representation of feature
        """
        return {
            "name": safe_get_attr(feature, "name"),
            "id": feature.get_id(),
            "code": safe_get_attr(feature, "code"),
            "required": False,
            "attributes": [
                AttributeSerializer.to_dict(attr, serialize_mandatory=False)
                for attr in feature.get_attribute_list()
            ],
            "commands": [
                CommandSerializer.to_dict(cmd, serialize_mandatory=False)
                for cmd in feature.get_command_list()
            ],
            "events": [
                EventSerializer.to_dict(event, serialize_mandatory=False)
                for event in feature.get_event_list()
            ],
        }


class ClusterSerializer:
    """Serializer for Cluster objects."""

    @staticmethod
    def to_dict(cluster):
        """Convert a Cluster object to dictionary representation.

        Args:
            cluster: Cluster object to serialize

        Returns:
            Dictionary representation of cluster
        """

        return {
            "name": safe_get_attr(cluster, "name"),
            "id": cluster.get_id(),
            "revision": cluster.get_revision(),
            "required": False,
            "attributes": [
                AttributeSerializer.to_dict(attr)
                for attr in sorted(
                    cluster.get_attribute_list(),
                    key=lambda x: (int(x.get_id(), 16), x.name),
                )
            ],
            "commands": [
                CommandSerializer.to_dict(cmd)
                for cmd in sorted(
                    cluster.get_command_list(),
                    key=lambda x: (int(x.get_id(), 16), x.name),
                )
            ],
            "events": [
                EventSerializer.to_dict(event)
                for event in sorted(
                    cluster.get_event_list(),
                    key=lambda x: (int(x.get_id(), 16), x.name),
                )
            ],
            "features": [
                FeatureSerializer.to_dict(feature)
                for feature in sorted(
                    cluster.get_feature_list(),
                    key=lambda x: (int(x.get_id(), 16), x.name),
                )
            ],
        }


class DeviceSerializer:
    """Serializer for Device objects."""

    @staticmethod
    def to_dict(device):
        """Convert a Device object to dictionary representation.

        Args:
            device: Device object to serialize

        Returns:
            Dictionary representation of device
        """
        result = {
            "name": safe_get_attr(device, "name"),
            "id": device.get_id(),
            "revision": safe_get_attr(device, "revision"),
            "clusters": [
                {
                    "name": safe_get_attr(cluster, "name"),
                    "id": cluster.get_id(),
                    "type": (
                        "server"
                        if safe_get_attr(cluster, "server_cluster")
                        else (
                            "client"
                            if safe_get_attr(cluster, "client_cluster")
                            else None
                        )
                    ),
                    "required": (
                        True
                        if cluster.is_mandatory
                        else (
                            "conditional" if cluster.mandatory_with_condition else False
                        )
                    ),
                    "features": safe_get_attr(cluster, "feature_name_list", []),
                    "commands": safe_get_attr(cluster, "command_name_list", []),
                    "attributes": safe_get_attr(cluster, "attribute_name_list", []),
                }
                for cluster in sorted(
                    device.get_all_mandatory_clusters(),
                    key=lambda x: (int(x.get_id(), 16), x.name),
                )
            ],
        }
        return result
