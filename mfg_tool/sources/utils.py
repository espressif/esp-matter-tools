#!/usr/bin/env python3

# Copyright 2022 Espressif Systems (Shanghai) PTE LTD
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
Contains utilitiy functions for validating argument.
"""

import re
import sys
import enum
import logging
import csv
from bitarray import bitarray
from bitarray.util import ba2int

ROTATING_DEVICE_ID_UNIQUE_ID_LEN_BITS = 128
SERIAL_NUMBER_LEN = 16


# Lengths for manual pairing codes and qrcode
SHORT_MANUALCODE_LEN = 11
LONG_MANUALCODE_LEN = 21
QRCODE_LEN = 22


INVALID_PASSCODES = [00000000, 11111111, 22222222, 33333333, 44444444, 55555555,
                     66666666, 77777777, 88888888, 99999999, 12345678, 87654321]


class CalendarTypes(enum.Enum):
    Buddhist = 0
    Chinese = 1
    Coptic = 2
    Ethiopian = 3
    Gregorian = 4
    Hebrew = 5
    Indian = 6
    Islamic = 7
    Japanese = 8
    Korean = 9
    Persian = 10
    Taiwanese = 11

class ProductFinish(enum.Enum):
    other = 0
    matte = 1
    satin = 2
    polished = 3
    rugged = 4
    fabric = 5


class ProductColor(enum.Enum):
    black = 0
    navy = 1
    green = 2
    teal = 3
    maroon = 4
    purple = 5
    olive = 6
    gray = 7
    blue = 8
    lime = 9
    aqua = 10
    red = 11
    fuchsia = 12
    yellow = 13
    white = 14
    nickel = 15
    chrome = 16
    brass = 17
    copper = 18
    silver = 19
    gold = 20

def VERIFY_OR_EXIT(condition, message = None):
    """
    Verify a condition and exit if it fails.

    Args:
        condition: Boolean condition to verify
        message: Error message to log and include in exit
    """
    if not condition:
        if message:
            logging.error(message)
        sys.exit(1)

def VERIFY_OR_RAISE(condition, message=None):
    """
    Verify a condition and raise an exception if it fails.

    Args:
        condition: Boolean condition to verify
        message: Error message to log and include in exception

    Raises:
        AssertionError: If the condition is False
    """
    if not condition:
        if message:
            logging.error(message)
        raise AssertionError(message)

def vid_pid_str(vid, pid):
    return '_'.join([hex(vid)[2:], hex(pid)[2:]])


def disc_pin_str(discriminator, passcode):
    return '_'.join([hex(discriminator)[2:], hex(passcode)[2:]])


# Checks if the input string is a valid hex string
def ishex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# Validate the input string length against the min and max length
def check_str_range(s, min_len, max_len, name):
    VERIFY_OR_EXIT(not(s and ((len(s) < min_len) or (len(s) > max_len))), f'{name} must be between {min_len} and {max_len} characters')


# Validate the date format
def check_date_format(date_str):
    VERIFY_OR_EXIT(not(date_str and not re.match(r'^\d{8}?$', date_str[0:8])), "First 8 bytes should be in ISO 8601 format YYYYMMDD (e.g., 20250416), last 8 can be anything specific to the manufacturer")

# Validate the input integer range
def check_int_range(value, min_value, max_value, name):
    VERIFY_OR_EXIT(not(value and ((value < min_value) or (value > max_value))), f'{name} is out of range, should be in range [{min_value}, {max_value}]')



# Validates discriminator and passcode
def validate_commissionable_data(args):
    check_int_range(args.discriminator, 0x0000, 0x0FFF, 'Discriminator')
    check_int_range(args.discovery_mode, 0, 7, 'Discovery mode')
    if args.passcode is not None:
        VERIFY_OR_EXIT(not((args.passcode < 0x0000001 and args.passcode > 0x5F5E0FE) or (args.passcode in INVALID_PASSCODES)), f'Invalid passcode {args.passcode}')

# Validate the device instance information
def validate_device_instance_info(args):
    check_int_range(args.product_id, 0x0000, 0xFFFF, 'Product id')
    check_int_range(args.vendor_id, 0x0000, 0xFFFF, 'Vendor id')
    check_int_range(args.hw_ver, 0x0000, 0xFFFF, 'Hardware version')
    check_str_range(args.serial_num, 1, SERIAL_NUMBER_LEN, 'Serial number')
    check_str_range(args.vendor_name, 1, 32, 'Vendor name')
    check_str_range(args.product_name, 1, 32, 'Product name')
    check_str_range(args.hw_ver_str, 1, 64, 'Hardware version string')
    check_str_range(args.mfg_date, 8, 16, 'Manufacturing date')
    check_str_range(args.rd_id_uid, 32, 32, 'Rotating device Unique id')
    check_str_range(args.part_number, 1, 32, 'Part number')
    check_date_format(args.mfg_date)


# Validate the device information: calendar types and fixed labels
def validate_device_info(args):
    # Validate the input calendar types
    if args.calendar_types is not None:
        if not (set(args.calendar_types) <= set(CalendarTypes.__members__)):
            invalid_types = set(args.calendar_types).union(set(CalendarTypes.__members__)) - set(CalendarTypes.__members__)
            logging.error('Unknown calendar type/s: %s', invalid_types)
            logging.error('Supported calendar types: %s', ', '.join(CalendarTypes.__members__))
            sys.exit(1)

    if args.fixed_labels is not None:
        for fl in args.fixed_labels:
            # Validate fixed label format: <endpoint_id>/<label_name>/<label_value>
            # Examples of valid fixed labels:
            # "0/orientation/up"
            VERIFY_OR_EXIT(re.match(r'^([0-9a-fA-F]{1,4})/(.{1,16})/(.{1,16})$', fl), f'Invalid fixed label: {fl}')

# Validates the attestation related arguments
def validate_attestation_info(args):
    # DAC key and DAC cert both should be present or none
    VERIFY_OR_EXIT((args.dac_key is not None) == (args.dac_cert is not None), "dac_key and dac_cert should be both present or none")
    VERIFY_OR_EXIT(not(args.dac_key is not None and args.pai is False), "Please provide PAI certificate along with DAC certificate and DAC key")

    # Validate the input certificate type, if DAC is not present
    if args.dac_key is None and args.dac_cert is None:
        if args.paa:
            logging.info('Input Root certificate type PAA')
        elif args.pai:
            logging.info('Input Root certificate type PAI')
        else:
            logging.info('Do not include the device attestation certificates and keys in partition binaries')

        # Check if Key and certificate are present
        VERIFY_OR_EXIT(not((args.paa or args.pai) and (args.key is None or args.cert is None)), 'CA key and certificate are required to generate DAC key and certificate')


# Validates DS peripheral related arguments
def validate_ds_peripheral_info(args):
    VERIFY_OR_EXIT(not(args.ds_peripheral and args.target.lower() != "esp32h2"), "DS peripheral is only supported for esp32h2 target")
    VERIFY_OR_EXIT(not(args.ds_peripheral and args.efuse_key_id == -1), "--efuse-key-id <value> is required when -ds or --ds-peripheral option is used")
    VERIFY_OR_EXIT(args.ds_peripheral is None or (not args.port or args.count == 1),"Port not specified or number of partitions count is greater than 1")

# Validates few basic cluster related arguments: product-label and product-url
def validate_basic_cluster_info(args):
    check_str_range(args.product_label, 1, 64, 'Product Label')
    check_str_range(args.product_url, 1, 256, 'Product URL')

# Validates the input arguments, this calls the above functions
def validate_args(args):
    # csv and mcsv both should present or none
    VERIFY_OR_EXIT((args.csv is not None) == (args.mcsv is not None), "csv and mcsv should be both present or none")
    if args.mcsv is not None:
        # Read the number of lines in mcsv file
        with open(args.mcsv, 'r', newline='') as f:
            csv_reader = csv.reader(f)
            # Count rows properly even when fields contain newlines
            row_count = sum(1 for row in csv_reader)

        # Subtract 1 for the header row
        args.count = row_count - 1

    validate_commissionable_data(args)
    validate_device_instance_info(args)
    validate_device_info(args)
    validate_attestation_info(args)
    validate_ds_peripheral_info(args)
    validate_basic_cluster_info(args)

    # If discriminator/passcode/DAC/serial_number/rotating_device_id is present
    # then we are restricting the number of partitions to 1
    if (args.discriminator is not None
            or args.passcode is not None
            or args.dac_key is not None
            or args.serial_num is not None
            or args.rd_id_uid is not None):
        VERIFY_OR_EXIT(args.count == 1, 'Number of partitions should be 1 when discriminator or passcode or DAC or serial number or rotating device id is present')

    logging.info('Number of manufacturing NVS images to generate: {}'.format(args.count))


# Supported Calendar types is stored as a bit array in one uint32_t.
def calendar_types_to_uint32(calendar_types):
    # In validate_device_info() we have already verified that the calendar types are valid
    result = bitarray(32, endian='little')
    result.setall(0)
    for calendar_type in calendar_types:
        result[CalendarTypes[calendar_type].value] = 1
    return ba2int(result)


# get_fixed_label_dict() converts the list of strings to per endpoint dictionaries.
# example input  : ['0/orientation/up', '1/orientation/down', '2/orientation/down']
# example outout : {'0': [{'orientation': 'up'}], '1': [{'orientation': 'down'}], '2': [{'orientation': 'down'}]}
def get_fixed_label_dict(fixed_labels):
    fl_dict = {}
    for fl in fixed_labels:
        _l = fl.split('/')

        VERIFY_OR_EXIT(len(_l) == 3, f'Invalid fixed label: {fl}')
        VERIFY_OR_EXIT(ishex(_l[0]), f'Invalid fixed label: {fl}')
        VERIFY_OR_EXIT((len(_l[1]) > 0 and len(_l[1]) < 16), f'Invalid fixed label: {fl}')
        VERIFY_OR_EXIT((len(_l[2]) > 0 and len(_l[2]) < 16), f'Invalid fixed label: {fl}')

        if _l[0] not in fl_dict.keys():
            fl_dict[_l[0]] = list()

        fl_dict[_l[0]].append({_l[1]: _l[2]})

    return fl_dict


# get_supported_modes_dict() converts the list of strings to per endpoint dictionaries.
# example with semantic tags
# input  : ['0/label1/1/"1\0x8000, 2\0x8000" 1/label2/1/"1\0x8000, 2\0x8000"']
# outout : {'1': [{'Label': 'label1', 'Mode': 0, 'Semantic_Tag': [{'value': 1, 'mfgCode': 32768}, {'value': 2, 'mfgCode': 32768}]}, {'Label': 'label2', 'Mode': 1, 'Semantic_Tag': [{'value': 1, 'mfgCode': 32768}, {'value': 2, 'mfgCode': 32768}]}]}

# example without semantic tags
# input  : ['0/label1/1 1/label2/1']
# outout : {'1': [{'Label': 'label1', 'Mode': 0, 'Semantic_Tag': []}, {'Label': 'label2', 'Mode': 1, 'Semantic_Tag': []}]}

def get_supported_modes_dict(supported_modes):
    output_dict = {}

    for mode_str in supported_modes:
        mode_label_strs = mode_str.split('/')
        mode = mode_label_strs[0]
        label = mode_label_strs[1]
        ep = mode_label_strs[2]

        semantic_tags = ''
        if (len(mode_label_strs) == 4):
            semantic_tag_strs = mode_label_strs[3].split(', ')
            semantic_tags = [{"value": int(v.split('\\')[0]), "mfgCode": int(v.split('\\')[1], 16)} for v in semantic_tag_strs]

        mode_dict = {"Label": label, "Mode": int(mode), "Semantic_Tag": semantic_tags}

        if ep in output_dict:
            output_dict[ep].append(mode_dict)
        else:
            output_dict[ep] = [mode_dict]

    return output_dict
