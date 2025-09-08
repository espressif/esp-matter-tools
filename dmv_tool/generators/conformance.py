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

from dmv_tool.generators.helpers import convert_to_snake_case, safe_get_attr

logger = logging.getLogger(__name__)


class Conformance:
    """Conformance class for handling conformance information."""

    def __init__(self):
        self.type = None  # mandatory, optional, otherwise, etc.
        self.condition = None  # Nested condition structure
        self.feature_map = {}  # Map of feature codes to feature objects

    def to_dict(self, attribute_map=None):
        """Convert conformance object to dictionary representation.

        Args:
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Dictionary representation of conformance
        """
        result = {"type": safe_get_attr(self, "type")}
        if safe_get_attr(self, "condition"):
            if attribute_map:
                result["condition"] = self._replace_attribute_and_command_names(
                    self.condition, attribute_map
                )
            else:
                result["condition"] = self.condition
        return result

    def _replace_attribute_and_command_names(self, condition, attribute_map):
        """Recursively replace attribute and command names with their IDs in the condition.

        Args:
            condition: The condition to process
            attribute_map: Dictionary mapping attribute names to their IDs

        Returns:
            Updated condition with replaced names
        """
        if isinstance(condition, dict):
            if "attribute" in condition:
                attr_name = condition["attribute"]
                if attr_name in attribute_map:
                    return {"attribute": attribute_map[attr_name]}
                return condition
            elif "command" in condition:
                cmd_name = condition["command"]
                if cmd_name in attribute_map:
                    return {
                        "command": attribute_map[cmd_name][0],
                        "flag": attribute_map[cmd_name][1],
                    }
                return condition
            else:
                return {
                    key: self._replace_attribute_and_command_names(value, attribute_map)
                    for key, value in sorted(condition.items())
                }
        elif isinstance(condition, list):
            return [
                self._replace_attribute_and_command_names(item, attribute_map)
                for item in condition
            ]
        return condition

    def has_feature(self, feature_code):
        """Check if conformance involves a specific feature.

        Args:
            feature_code: Feature code to check

        Returns:
            True if conformance involves the feature, False otherwise
        """
        if not self.condition:
            return False
        feature_obj = self.feature_map.get(feature_code)
        if not feature_obj:
            return False
        feature_name = feature_obj.func_name
        return _condition_has_feature(self.condition, feature_name)


def _condition_has_feature(condition, feature_code):
    """Recursively check if condition references a specific feature.

    Args:
        condition: The condition to check
        feature_code: Feature code to look for

    Returns:
        True if condition references the feature, False otherwise
    """
    if "feature" in condition and condition["feature"] == feature_code:
        return True
    return False


def parse_conformance(conformance_elem, feature_map):
    """Parse a conformance element from XML.

    Args:
        conformance_elem: XML conformance element
        feature_map: Dictionary mapping feature codes to feature objects

    Returns:
        Parsed Conformance object or None
    """
    if conformance_elem is None:
        return None
    conformance = Conformance()
    conformance.feature_map = feature_map
    if conformance_elem.tag == "mandatoryConform":
        conformance.type = "mandatory"
    elif conformance_elem.tag == "optionalConform":
        conformance.type = "optional"
    elif conformance_elem.tag == "deprecateConform":
        conformance.type = "deprecated"
    elif conformance_elem.tag == "disallowConform":
        conformance.type = "disallowed"
    else:
        conformance.type = conformance_elem.tag

    for child in conformance_elem:
        if (
            child.tag is not None
            and child.tag.endswith("Term")
            or child.tag
            in [
                "attribute",
                "feature",
                "command",
            ]
        ):
            conformance.condition = _parse_condition(child, feature_map)
            break  # We only expect one main condition
    return conformance


def parse_otherwise_conformance(otherwise_elem, feature_map):
    """Parse an 'otherwiseConform' element from XML.

    Args:
        otherwise_elem: XML otherwise element
        feature_map: Dictionary mapping feature codes to feature objects

    Returns:
        Parsed Conformance object or None
    """
    if otherwise_elem is None:
        return None

    conformance = Conformance()
    conformance.type = "otherwise"
    conformance.feature_map = feature_map

    sub_conditions = {}
    for child in otherwise_elem:
        if child.tag in [
            "mandatoryConform",
            "optionalConform",
            "deprecateConform",
            "disallowConform",
        ]:
            child_type = child.tag.replace("Conform", "")
            sub_condition = {}
            for subchild in child:
                if (
                    subchild.tag is not None
                    and subchild.tag.endswith("Term")
                    or subchild.tag
                    in [
                        "attribute",
                        "feature",
                        "command",
                    ]
                ):
                    parsed_condition = _parse_condition(subchild, feature_map)
                    if parsed_condition:
                        # Merge the parsed condition with any existing attributes
                        if isinstance(parsed_condition, dict):
                            sub_condition.update(parsed_condition)
                        else:
                            sub_condition["condition"] = parsed_condition
                    break

            # If no condition was parsed but we have attributes, or if we have both condition and attributes
            sub_conditions[child_type] = sub_condition if sub_condition else True
    conformance.condition = sub_conditions if sub_conditions else None
    return conformance


def _parse_condition(elem, feature_map):
    """Recursively parse a condition element into a nested dictionary structure.

    Args:
        elem: XML element to parse
        feature_map: Dictionary mapping feature codes to feature objects

    Returns:
        Parsed condition dictionary or None
    """
    if elem is None:
        return None
    if elem.tag == "attribute":
        return {"attribute": elem.get("name")}
    if elem.tag == "command":
        return {"command": elem.get("name")}

    if elem.tag == "feature":
        feature_code = elem.get("name")
        if feature_code in feature_map.keys():
            return {"feature": convert_to_snake_case(feature_map[feature_code].name)}
        else:
            logger.error(f"Feature {feature_code} not found in feature map")
            # Return error code instead of continuing with a conformance object
            return None  # Returning None indicates the feature wasn't found

    condition_type = elem.tag
    if condition_type is not None and condition_type.endswith("Term"):
        condition_type = condition_type.replace("Term", "")

    if condition_type in ["and", "or"]:
        subconditions = []
        for child in elem:
            subcondition = _parse_condition(child, feature_map)
            if subcondition:
                subconditions.append(subcondition)

        if len(subconditions) > 1:
            return {condition_type: subconditions}
        elif len(subconditions) == 1:
            return {condition_type: subconditions[0]}

    elif condition_type == "not":
        for child in elem:
            subcondition = _parse_condition(child, feature_map)
            if subcondition:
                return {condition_type: subcondition}
    return None


def check_conformance_restrictions(feature_map, element):
    """Check if any conformance restrictions are applied to the element

    :param feature_map: The feature map.
    :param element: The element from the cluster XML file.
    :returns: True if the event should be processed, False otherwise.

    """
    element_name = element.get("name", "Unknown")
    disallow_conform = element.find("disallowConform")
    if disallow_conform is not None:
        logger.debug(f"Skipping - disallow conformance for element {element_name}")
        return True

    deprecate_conform = element.find("deprecateConform")
    if deprecate_conform is not None:
        logger.debug(f"Skipping - deprecated element {element_name}")
        return True

    provisional_conform = element.find("provisionalConform")
    if provisional_conform is not None:
        logger.debug(f"Skipping - provisional element {element_name}")
        return True

    otherwise_conform = element.find("otherwiseConform")
    if otherwise_conform is not None:
        first_child = next(iter(otherwise_conform), None)
        if first_child is not None and first_child.tag == "mandatoryConform":
            return False
        elif (
            first_child is not None
            and first_child.tag == "provisionalConform"
            or first_child.tag == "deprecateConform"
            or first_child.tag == "disallowConform"
        ):
            logger.debug(f"Skipping - element {element_name} due to {first_child.tag}")
            return True

    optional_conform = element.find("optionalConform")
    if optional_conform is not None:
        cond = optional_conform.find("condition")
        if cond is not None and cond.get("name") == "Zigbee":
            logger.debug(f"Skipping - Zigbee specific element {element_name}")
            return True

    if feature_map is not None:
        # check if feature is deprecated or disallowed
        conformance = (
            element.find("mandatoryConform")
            or element.find("optionalConform")
            or element.find("otherwiseConform")
        )
        all_features_list = (
            conformance.findall(".//feature") if conformance is not None else []
        )
        for feature in all_features_list:
            feature_name = feature.get("name")
            if feature_name not in feature_map:
                logger.debug(
                    f"Skipping - feature {feature_name} not found in feature map for element {element_name}"
                )
                return True
    return False


def match_conformance_items(feature, item_list):
    """Get list of items matched with current feature

    :param feature: feature object
    :param item_list: list of items to check for match
    :returns: A list of commands that have conformance with the given feature.

    """
    matched_items = []
    for item in item_list:
        conformance = safe_get_attr(item, "conformance")
        if not conformance:
            continue

        if conformance.type == "mandatory" and conformance.has_feature(feature.code):
            matched_items.append(item)
        if (
            conformance.type == "otherwise"
            and conformance.condition.get("mandatory", False)
            and conformance.has_feature(feature.code)
        ):
            matched_items.append(item)
    return matched_items
