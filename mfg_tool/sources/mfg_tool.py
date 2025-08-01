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
Script to generate Matter factory NVS partition image, Onboarding codes, and QR codes.
"""

import os
import sys
import csv
import uuid
import shutil
import base64
import random
import logging
import binascii
import argparse
import pyqrcode
from datetime import datetime
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization

from chip_nvs import (
    chip_nvs_get_config_csv, chip_get_keys_as_csv, chip_nvs_map_update,
    chip_factory_update, chip_factory_append, chip_get_values_as_csv,
    chip_factory_get_val, chip_nvs_map_append_config_csv
)
from utils import (
    INVALID_PASSCODES, vid_pid_str, SERIAL_NUMBER_LEN,
    ROTATING_DEVICE_ID_UNIQUE_ID_LEN_BITS, ProductFinish, ProductColor,
    validate_args, calendar_types_to_uint32, get_fixed_label_dict,
    get_supported_modes_dict
)
from cert_utils import (
    build_certificate, convert_x509_cert_from_pem_to_der, store_keypair_as_raw,
    convert_private_key_from_pem_to_der, extract_common_name, load_cert_from_file,
    validate_certificates
)
from esp_secure_cert import configure_ds
from esp_secure_cert.tlv_format import (
    tlv_priv_key_t, tlv_priv_key_type_t, generate_partition_ds,
    generate_partition_no_ds
)

# In order to made the esp-matter-mfg-tool standalone we copied few dependencies from esp-idf
# and connectedhomeip to deps/ directory.
# TODO: Remove the dependencies from deps/ once available on pypi
from deps.spake2p import generate_verifier
from deps.mfg_gen import generate
from deps.generate_setup_payload import SetupPayload, CommissioningFlow

PAI = {
    'cert_pem': None,
    'cert_der': None,
    'key_pem': None,
    'key_der': None,
}

OUT_DIR = {
    'top': None,
    'chip': None,
}

OUT_FILE = {
    'config_csv': None,
    'mcsv': None,
    'pin_csv': None,
    'pin_disc_csv': None,
    'cn_dac_csv': None
}

# Supported log levels, mapping string values required for argument
# parsing into logging constants
__LOG_LEVELS__ = {
    'info': logging.INFO,
    'error': logging.ERROR,
}

UUIDs = list()

def generate_passcodes(args):
    iter_count_max = 10000
    salt_len_max = 32
    with open(OUT_FILE['pin_csv'], 'w', newline='') as f:
        writer = csv.writer(f)
        if args.enable_dynamic_passcode:
            writer.writerow(["Index", "Iteration Count", "Salt"])
        else:
            writer.writerow(["Index", "PIN Code", "Iteration Count", "Salt", "Verifier"])
        for i in range(0, args.count):
            salt = os.urandom(salt_len_max)
            if args.enable_dynamic_passcode:
                writer.writerow([i, iter_count_max, base64.b64encode(salt).decode('utf-8')])
            else:
                if args.passcode:
                    passcode = args.passcode
                else:
                    passcode = random.randint(1, 99999998)
                    if passcode in INVALID_PASSCODES:
                        passcode -= 1
                verifier = generate_verifier(passcode, salt, iter_count_max)
                writer.writerow([i, passcode, iter_count_max, base64.b64encode(salt).decode('utf-8'), base64.b64encode(verifier).decode('utf-8')])


def generate_discriminators(args):
    discriminators = list()

    # If discriminator is provided, use it
    if args.discriminator:
        discriminators.append(args.discriminator)
    else:
        for i in range(args.count):
            discriminators.append(random.randint(0x0000, 0x0FFF))

    return discriminators


# Append discriminator to each line of the passcode file
def append_discriminator(discriminator):
    with open(OUT_FILE['pin_csv'], 'r') as fd:
        lines = fd.readlines()

    lines[0] = ','.join([lines[0].strip(), 'Discriminator'])
    for i in range(1, len(lines)):
        lines[i] = ','.join([lines[i].strip(), str(discriminator[i - 1])])

    with open(OUT_FILE['pin_disc_csv'], 'w') as fd:
        fd.write('\n'.join(lines) + '\n')

    os.remove(OUT_FILE['pin_csv'])


# Generates the csv file containing chip specific keys and keys provided by user in csv file
def generate_config_csv(args):
    logging.info("Generating Config CSV...")
    csv_data = chip_nvs_get_config_csv()

    with open(OUT_FILE['config_csv'], 'w') as f:
        f.write(csv_data)


def write_chip_mcsv_header(args):
    logging.info('Writing chip manifest CSV header...')
    mcsv_header = chip_get_keys_as_csv()
    with open(OUT_FILE['mcsv'], 'w', newline='') as f:
        header_values = mcsv_header.split(',')
        writer = csv.writer(f)
        writer.writerow(header_values)


def append_chip_mcsv_row(row_data):
    logging.info('Appending chip master CSV row...')
    with open(OUT_FILE['mcsv'], 'a', newline='') as f:
        row_values = row_data.split(',')
        writer = csv.writer(f)
        writer.writerow(row_values)

def generate_pai(args, ca_key, ca_cert, out_key, out_cert):
    vendor_id = hex(args.vendor_id)[2:].upper()
    product_id = hex(args.product_id)[2:].upper()
    common_name = "{} PAI {}".format(args.cn_prefix, "00") if args.cn_prefix else "MATTER TEST PAI " + str(random.randint(10, 99))

    build_certificate(
        vendor_id=vendor_id,
        product_id=product_id,
        ca_cert_file=ca_cert,
        ca_privkey_file=ca_key,
        out_cert_file=out_cert,
        out_key_file=out_key,
        is_pai=True,
        common_name=common_name,
        valid_from=args.valid_from,
        lifetime=args.lifetime)

    logging.info('Generated PAI certificate: {}'.format(out_cert))
    logging.info('Generated PAI private key: {}'.format(out_key))


def generate_dac(iteration, args, ca_key, ca_cert):
    out_key_pem = os.sep.join([OUT_DIR['top'], UUIDs[iteration], 'internal', 'DAC_key.pem'])
    out_private_key_der = out_key_pem.replace('key.pem', 'key.der')
    out_cert_pem = out_key_pem.replace('key.pem', 'cert.pem')
    out_cert_der = out_key_pem.replace('key.pem', 'cert.der')
    out_private_key_bin = out_key_pem.replace('key.pem', 'private_key.bin')
    out_public_key_bin = out_key_pem.replace('key.pem', 'public_key.bin')

    vendor_id = hex(args.vendor_id)[2:].upper()
    product_id = hex(args.product_id)[2:].upper()
    common_name = UUIDs[iteration]

    build_certificate(
        vendor_id=vendor_id,
        product_id=product_id,
        ca_cert_file=ca_cert,
        ca_privkey_file=ca_key,
        out_cert_file=out_cert_pem,
        out_key_file=out_key_pem,
        is_pai=False,
        common_name=common_name,
        valid_from=args.valid_from,
        lifetime=args.lifetime)

    logging.info('Generated DAC certificate: {}'.format(out_cert_pem))
    logging.info('Generated DAC private key: {}'.format(out_key_pem))

    convert_x509_cert_from_pem_to_der(out_cert_pem, out_cert_der)
    logging.info('Generated DAC certificate in DER format: {}'.format(out_cert_der))

    store_keypair_as_raw(out_key_pem, out_private_key_bin, out_public_key_bin)
    logging.info('Generated DAC private key in binary format: {}'.format(out_private_key_bin))
    logging.info('Generated DAC public key in binary format: {}'.format(out_public_key_bin))
    convert_private_key_from_pem_to_der(out_key_pem, out_private_key_der)
    return out_cert_der, out_private_key_bin, out_public_key_bin, out_private_key_der


def use_dac_from_args(args):
    logging.info('Using DAC from command line arguments...')
    logging.info('DAC Certificate: {}'.format(args.dac_cert))
    logging.info('DAC Private Key: {}'.format(args.dac_key))

    # There should be only one UUID in the UUIDs list if DAC is specified
    out_cert_der = os.sep.join([OUT_DIR['top'], UUIDs[0], 'internal', 'DAC_cert.der'])
    out_private_key_bin = out_cert_der.replace('cert.der', 'private_key.bin')
    out_public_key_bin = out_cert_der.replace('cert.der', 'public_key.bin')
    out_private_key_der = out_cert_der.replace('cert.der', 'key.der')

    convert_x509_cert_from_pem_to_der(args.dac_cert, out_cert_der)
    logging.info('Generated DAC certificate in DER format: {}'.format(out_cert_der))

    store_keypair_as_raw(args.dac_key, out_private_key_bin, out_public_key_bin)
    logging.info('Generated DAC private key in binary format: {}'.format(out_private_key_bin))
    logging.info('Generated DAC public key in binary format: {}'.format(out_public_key_bin))
    convert_private_key_from_pem_to_der(args.dac_key, out_private_key_der)

    return out_cert_der, out_private_key_bin, out_public_key_bin, out_private_key_der


def is_valid_uuid(uuid_str: str) -> bool:
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


def setup_out_dirs(vid, pid, count, outdir, arg_dac_cert):
    OUT_DIR['top'] = os.sep.join([outdir, vid_pid_str(vid, pid)])
    OUT_DIR['stage'] = os.sep.join([outdir, vid_pid_str(vid, pid), 'staging'])

    os.makedirs(OUT_DIR['top'], exist_ok=True)
    os.makedirs(OUT_DIR['stage'], exist_ok=True)

    OUT_FILE['config_csv'] = os.sep.join([OUT_DIR['stage'], 'config.csv'])
    OUT_FILE['mcsv'] = os.sep.join([OUT_DIR['stage'], 'master.csv'])
    OUT_FILE['pin_csv'] = os.sep.join([OUT_DIR['stage'], 'pin.csv'])
    OUT_FILE['pin_disc_csv'] = os.sep.join([OUT_DIR['stage'], 'pin_disc.csv'])
    OUT_FILE['cn_dac_csv'] = os.sep.join([OUT_DIR['top'], 'cn_dacs-{}.csv'.format(datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))])

    # If user provided the DAC, then count is 1 and this gets called only after
    # arguments have been validated. So we can safely assume that count is 1, and return
    if arg_dac_cert:
        subject_cn = extract_common_name(load_cert_from_file(arg_dac_cert).subject)
        if subject_cn and is_valid_uuid(subject_cn):
            UUIDs.append(subject_cn)
            os.makedirs(os.sep.join([OUT_DIR['top'], subject_cn, 'internal']), exist_ok=True)
            return

    # Create directories to store the generated files
    for i in range(count):
        uuid_str = str(uuid.uuid4())
        UUIDs.append(uuid_str)
        os.makedirs(os.sep.join([OUT_DIR['top'], uuid_str, 'internal']), exist_ok=True)


def generate_passcodes_and_discriminators(args):
    # Generate passcodes using spake2p tool
    generate_passcodes(args)
    # Randomly generate discriminators
    discriminators = generate_discriminators(args)
    # Append discriminators to passcodes file
    append_discriminator(discriminators)


def write_cn_dac_csv_header():
    with open(OUT_FILE['cn_dac_csv'], 'a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["CN", "certs"])
    return

def write_csv_files(args):
    generate_config_csv(args)
    write_chip_mcsv_header(args)
    write_cn_dac_csv_header()


def setup_root_certs(args):
    # If PAA is passed as input, then generate PAI certificate
    if args.paa:
        # output file names
        PAI['cert_pem'] = os.sep.join([OUT_DIR['stage'], 'pai_cert.pem'])
        PAI['cert_der'] = os.sep.join([OUT_DIR['stage'], 'pai_cert.der'])
        PAI['key_pem'] = os.sep.join([OUT_DIR['stage'], 'pai_key.pem'])

        generate_pai(args, args.key, args.cert, PAI['key_pem'], PAI['cert_pem'])
        convert_x509_cert_from_pem_to_der(PAI['cert_pem'], PAI['cert_der'])
        logging.info('Generated PAI certificate in DER format: {}'.format(PAI['cert_der']))

    # If PAI is passed as input, generate DACs
    elif args.pai:
        PAI['cert_pem'] = args.cert
        PAI['key_pem'] = args.key
        PAI['cert_der'] = os.sep.join([OUT_DIR['stage'], 'pai_cert.der'])

        convert_x509_cert_from_pem_to_der(PAI['cert_pem'], PAI['cert_der'])
        logging.info('Generated PAI certificate in DER format: {}'.format(PAI['cert_der']))


def overwrite_values_in_mcsv(args, index):
    with open(args.mcsv, 'r') as mcsvf:
        mcsv_dict = list(csv.DictReader(mcsvf))[index]
        with open(args.csv, 'r') as csvf:
            csv_reader = csv.reader(csvf, delimiter=',')
            current_namespace = 'chip-factory'
            for csv_data in csv_reader:
                if 'namespace' in csv_data:
                    current_namespace = csv_data[0]
                else:
                    chip_nvs_map_update(current_namespace, csv_data[0], csv_data[1], csv_data[2], mcsv_dict[csv_data[0]])


def append_cn_dac_to_csv(common_name, cert_path):
    with open(OUT_FILE['cn_dac_csv'], 'a', newline='') as csv_file:
        device_cert_contents = load_cert_from_file(cert_path).public_bytes(serialization.Encoding.PEM).decode('utf-8')
        writer = csv.writer(csv_file)
        writer.writerow([common_name, device_cert_contents])

# This function generates the DACs, picks the commissionable data from the already present csv file,
# and generates the onboarding payloads, and writes everything to the master csv
def write_per_device_unique_data(args):
    with open(OUT_FILE['pin_disc_csv'], 'r') as csvf:
        pin_disc_dict = csv.DictReader(csvf)

        for row in pin_disc_dict:
            chip_factory_update('discriminator', row['Discriminator'])
            chip_factory_update('iteration-count', row['Iteration Count'])
            chip_factory_update('salt', row['Salt'])
            if not args.enable_dynamic_passcode:
                chip_factory_update('verifier', row['Verifier'])
            if args.paa or args.pai:
                if args.dac_key is not None and args.dac_cert is not None:
                    dacs = use_dac_from_args(args)
                else:
                    dacs = generate_dac(int(row['Index']), args, PAI['key_pem'], PAI['cert_pem'])

                if not args.dac_in_secure_cert:
                    chip_factory_update('dac-cert', os.path.abspath(dacs[0]))
                    chip_factory_update('dac-key', os.path.abspath(dacs[1]))
                    chip_factory_update('dac-pub-key', os.path.abspath(dacs[2]))
                    chip_factory_update('pai-cert', os.path.abspath(PAI['cert_der']))
                else:
                # esp secure cert partition
                    secure_cert_partition_file_path = os.sep.join([OUT_DIR['top'], UUIDs[int(row['Index'])], UUIDs[int(row['Index'])] + '_esp_secure_cert.bin'])
                    if args.ds_peripheral:
                        if args.port and args.count == 1:
                            esp_secure_cert_data_dir = 'esp_secure_cert_data'
                            if (os.path.exists(esp_secure_cert_data_dir) is False):
                                os.makedirs(esp_secure_cert_data_dir)
                            ecdsa_key_file = os.path.join(esp_secure_cert_data_dir, 'ecdsa_key.bin')

                            ecdsa_key_size = '256'
                            configure_ds.configure_efuse_for_ecdsa(args.target, args.port, ecdsa_key_file, None, esp_secure_cert_data_dir, ecdsa_key_size, os.path.abspath(dacs[3]), args.priv_key_pass, args.efuse_key_id)

                        priv_key = tlv_priv_key_t(key_type = tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY,
                                                  key_path = os.path.abspath(dacs[3]), key_pass = None)
                        priv_key.priv_key_len = 256
                        priv_key.efuse_key_id = args.efuse_key_id
                        generate_partition_ds(priv_key = priv_key, device_cert = os.path.abspath(dacs[0]),
                                              ca_cert = os.path.abspath(PAI['cert_der']), idf_target = args.target,
                                              op_file = secure_cert_partition_file_path)
                    else:
                        priv_key = tlv_priv_key_t(key_type = tlv_priv_key_type_t.ESP_SECURE_CERT_DEFAULT_FORMAT_KEY,
                                                  key_path = os.path.abspath(dacs[3]), key_pass = None)
                        generate_partition_no_ds(priv_key = priv_key, device_cert = os.path.abspath(dacs[0]),
                                                 ca_cert = os.path.abspath(PAI['cert_der']), idf_target = args.target,
                                                 op_file = secure_cert_partition_file_path)

                # appends the subject's common name and DAC certificate encoded as PEM to the csv file
                file_name = os.sep.join([OUT_DIR['top'], UUIDs[int(row['Index'])], "internal", "DAC_cert.pem"])
                if args.dac_key is not None and args.dac_cert is not None:
                    file_name = args.dac_cert

                subject_cn = extract_common_name(load_cert_from_file(file_name).subject)
                # If common name is not present, lets skip adding that entry to the csv file
                if subject_cn:
                    append_cn_dac_to_csv(subject_cn, file_name)
                else:
                    logging.warning("Skipping entry for device with index {} as common name is not present in the DAC certificate".format(row['Index']))

            # If serial number is not passed, then generate one
            if (args.serial_num is None):
                chip_factory_update('serial-num', binascii.b2a_hex(os.urandom(SERIAL_NUMBER_LEN)).decode('utf-8'))

            if (args.enable_rotating_device_id is True) and (args.rd_id_uid is None):
                chip_factory_update('rd-id-uid', binascii.b2a_hex(os.urandom(int(ROTATING_DEVICE_ID_UNIQUE_ID_LEN_BITS / 8))).decode('utf-8'))

            if (args.csv is not None and args.mcsv is not None):
                overwrite_values_in_mcsv(args, int(row['Index']))

            mcsv_row_data = chip_get_values_as_csv()
            append_chip_mcsv_row(mcsv_row_data)

            # Generate onboarding data
            if not args.enable_dynamic_passcode:
                generate_onboarding_data(args, int(row['Index']), int(chip_factory_get_val('discriminator')), int(row['PIN Code']))
        if args.paa or args.pai:
            logging.info("Generated CSV of Common Name and DAC: {}".format(OUT_FILE['cn_dac_csv']))


def organize_output_files(suffix, args):
    for i in range(len(UUIDs)):
        dest_path = os.sep.join([OUT_DIR['top'], UUIDs[i]])
        internal_path = os.sep.join([dest_path, 'internal'])

        if args.generate_bin:
            replace = os.sep.join([OUT_DIR['top'], 'bin', '{}-{}.bin'.format(suffix, str(i + 1))])
            replace_with = os.sep.join([dest_path, '{}-partition.bin'.format(UUIDs[i])])
            os.rename(replace, replace_with)

            if args.encrypt:
                 replace = os.sep.join([OUT_DIR['top'], 'keys', 'keys-{}-{}.bin'.format(suffix, str(i + 1))])
                 replace_with = os.sep.join([dest_path, '{}-keys-partition.bin'.format(UUIDs[i])])
                 os.rename(replace, replace_with)

        replace = os.sep.join([OUT_DIR['top'], 'csv', '{}-{}.csv'.format(suffix, str(i + 1))])
        replace_with = os.sep.join([internal_path, 'partition.csv'])
        os.rename(replace, replace_with)

        # Also copy the PAI certificate to the output directory
        if args.paa or args.pai:
            shutil.copy2(PAI['cert_der'], os.sep.join([internal_path, 'PAI_cert.der']))

        logging.info('Generated output files at: {}'.format(os.sep.join([OUT_DIR['top'], UUIDs[i]])))

    shutil.rmtree(os.sep.join([OUT_DIR['top'], 'bin']), ignore_errors=True)
    shutil.rmtree(os.sep.join([OUT_DIR['top'], 'csv']), ignore_errors=True)

    if args.encrypt:
        shutil.rmtree(os.sep.join([OUT_DIR['top'], 'keys']), ignore_errors=True)

def format_manual_code(manual_code, flow):
    if flow == CommissioningFlow.Standard:
        return f'{manual_code[:4]}-{manual_code[4:7]}-{manual_code[7:]}'
    else:
        return f'{manual_code[:4]}-{manual_code[4:7]}-{manual_code[7:11]}\n{manual_code[11:15]}-{manual_code[15:18]}-{manual_code[18:20]}-{manual_code[20:21]}'

def generate_summary(args):
    master_csv = os.sep.join([OUT_DIR['stage'], 'master.csv'])
    summary_csv = os.sep.join([OUT_DIR['top'], 'summary-{}.csv'.format(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))])

    with open(master_csv, 'r', newline='') as mcsvf:
        master_csv_reader = csv.reader(mcsvf)
        master_headers = next(master_csv_reader)
        master_rows = list(master_csv_reader)

        with open(OUT_FILE['pin_disc_csv'], 'r', newline='') as pdcsvf:
            pin_disc_dict = list(csv.DictReader(pdcsvf))

            with open(summary_csv, 'w', newline='') as scsvf:
                summary_writer = csv.writer(scsvf)

                # Prepare the header row
                header_row = master_headers[:]
                if not args.enable_dynamic_passcode:
                    header_row.extend(['pincode', 'qrcode', 'manualcode'])

                summary_writer.writerow(header_row)

                # Write each row
                for i, row in enumerate(pin_disc_dict):
                    if i < len(master_rows):
                        master_row = master_rows[i]
                        output_row = master_row[:]

                        if not args.enable_dynamic_passcode:
                            pincode = row['PIN Code']
                            discriminator = row['Discriminator']
                            payloads = SetupPayload(int(discriminator), int(pincode), args.discovery_mode,
                                                   CommissioningFlow(args.commissioning_flow),
                                                   args.vendor_id, args.product_id)
                            qrcode = payloads.generate_qrcode()
                            manualcode = format_manual_code(payloads.generate_manualcode(), args.commissioning_flow)

                            output_row.extend([pincode, qrcode, manualcode])

                        summary_writer.writerow(output_row)

def generate_partitions(suffix, size, encrypt, generate_partition_bin):
    partition_args = SimpleNamespace(fileid = None,
                                     version = 2,
                                     inputkey = None,
                                     outdir = OUT_DIR['top'],
                                     conf = OUT_FILE['config_csv'],
                                     values = OUT_FILE['mcsv'],
                                     size = hex(size),
                                     prefix = suffix,
                                     generate_bin = generate_partition_bin)
    if encrypt:
        partition_args.keygen = True
    else:
        partition_args.keygen = False
    partition_args.key_protect_hmac = False
    generate(partition_args)


def generate_onboarding_data(args, index, discriminator, passcode):
    payloads = SetupPayload(discriminator, passcode, args.discovery_mode, CommissioningFlow(args.commissioning_flow),
                            args.vendor_id, args.product_id)
    chip_qrcode = payloads.generate_qrcode()
    chip_manualcode = payloads.generate_manualcode()
    # ToDo: remove this if qrcode tool can handle the standard manual code format
    if args.commissioning_flow == CommissioningFlow.Standard:
        chip_manualcode = chip_manualcode[:4] + '-' + chip_manualcode[4:7] + '-' + chip_manualcode[7:]
    else:
        chip_manualcode = '"' + chip_manualcode[:4] + '-' + chip_manualcode[4:7] + '-' + chip_manualcode[7:11] + '\n' + chip_manualcode[11:15] + '-' + chip_manualcode[15:18] + '-' + chip_manualcode[18:20] + '-' + chip_manualcode[20:21] + '"'

    logging.info('Generated QR code: ' + chip_qrcode)
    logging.info('Generated manual code: ' + chip_manualcode)

    csv_data = 'qrcode,manualcode,discriminator,passcode\n'
    csv_data += chip_qrcode + ',' + chip_manualcode + ',' + str(discriminator) + ',' + str(passcode) + '\n'

    onboarding_data_file = os.sep.join([OUT_DIR['top'], UUIDs[index], '{}-onb_codes.csv'.format(UUIDs[index])])
    with open(onboarding_data_file, 'w') as f:
        f.write(csv_data)

    # Create QR code image as mentioned in the spec
    qrcode_file = os.sep.join([OUT_DIR['top'], UUIDs[index], '{}-qrcode.png'.format(UUIDs[index])])
    chip_qr = pyqrcode.create(chip_qrcode, version=2, error='M')
    chip_qr.png(qrcode_file, scale=6)

    logging.info('Generated onboarding data and QR Code')


def get_args():
    def any_base_int(s): return int(s, 0)

    parser = argparse.ArgumentParser(description='Manufacuring partition generator tool',
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=50))

    g_gen = parser.add_argument_group('General options')
    g_gen.add_argument('-n', '--count', type=any_base_int, default=1,
                       help='The number of manufacturing partition binaries to generate. Default is 1. \
                              If --csv and --mcsv are present, the number of lines in the mcsv file is used.')

    g_gen.add_argument('--target', default='esp32',
                       help='The platform type of device. eg: one of esp32, esp32c3, etc.')
    g_gen.add_argument('-s', '--size', type=any_base_int, default=0x6000,
                       help='The size of manufacturing partition binaries to generate. Default is 0x6000.')
    g_gen.add_argument('-e', '--encrypt', action='store_true', required=False,
                      help='Encrypt the factory parititon NVS binary')
    g_gen.add_argument('--log-level', default='info', choices=__LOG_LEVELS__.keys(),
                      help='Set the log level (default: %(default)s)')
    g_gen.add_argument('--outdir', default=os.path.join(os.getcwd(), 'out'),
                      help='The output directory for the generated files (default: %(default)s)')
    g_gen.add_argument('--no-bin', action='store_false', dest='generate_bin',
                        help='Do not generate the factory partition binary')

    g_commissioning = parser.add_argument_group('Commisioning options')
    g_commissioning.add_argument('--passcode', type=any_base_int,
                                 help='The passcode for pairing. Randomly generated if not specified.')
    g_commissioning.add_argument('--discriminator', type=any_base_int,
                                 help='The discriminator for pairing. Randomly generated if not specified.')
    g_commissioning.add_argument('-cf', '--commissioning-flow', type=any_base_int, default=0,
                                 help='Device commissioning flow, 0:Standard, 1:User-Intent, 2:Custom. \
                                          Default is 0.', choices=[0, 1, 2])
    g_commissioning.add_argument('-dm', '--discovery-mode', type=any_base_int, default=2,
                                 help='The discovery mode for commissionable device discovery. \
                                        2: BLE, 4: On-network, 6: BLE + On-network. Default is BLE.')
    g_commissioning.add_argument('--enable-dynamic-passcode', action="store_true", required=False,
                                 help='Enable dynamic passcode. If enabling this option, the generated binaries will \
                                         not include the spake2p verifier. so this option should work with a custom \
                                         CommissionableDataProvider which can generate random passcode and \
                                         corresponding verifier')

    g_dac = parser.add_argument_group('Device attestation credential options')
    g_dac.add_argument('--dac-in-secure-cert', action="store_true", required=False,
                        help='Store DAC in secure cert partition. By default, DAC is stored in nvs factory partition.')
    g_dac.add_argument('-lt', '--lifetime', default=36500, type=any_base_int,
                       help='Lifetime of the generated certificate. Default is 100 years if not specified, \
                              this indicate that certificate does not have well defined expiration date.')
    g_dac.add_argument('-vf', '--valid-from',
                       help='The start date for the certificate validity period in format <YYYY>-<MM>-<DD> [ <HH>:<MM>:<SS> ]. \
                              Default is current date.')
    g_dac.add_argument('-cn', '--cn-prefix', default='ESP32',
                       help='The common name prefix of the subject of the PAI certificate.')
    # If DAC is present then PAI key is not required, so it is marked as not required here
    # but, if DAC is not present then PAI key is required and that case is validated in validate_args()
    g_dac.add_argument('-c', '--cert', help='The input certificate file in PEM format.')
    g_dac.add_argument('-k', '--key', help='The input key file in PEM format.')
    g_dac.add_argument('-cd', '--cert-dclrn', help='The certificate declaration file in DER format.')
    g_dac.add_argument('--dac-cert', help='The input DAC certificate file in PEM format.')
    g_dac.add_argument('--dac-key', help='The input DAC private key file in PEM format.')
    g_dac.add_argument('-ds', '--ds-peripheral', action="store_true",
                       help='Use DS Peripheral in generating secure cert partition.')
    g_dac.add_argument('--efuse-key-id', type=int, choices=range(0, 6), default=-1,
                        help='Provide the efuse key_id which contains/will contain HMAC_KEY, default is 1')
    g_dac.add_argument('--port', dest='port', help='UART com port to which the ESP device is connected')
    g_dac.add_argument('--pwd', '--password', dest='priv_key_pass', help='The password associated with the private key')

    input_cert_group = g_dac.add_mutually_exclusive_group(required=False)
    input_cert_group.add_argument('--paa', action='store_true', help='Use input certificate as PAA certificate.')
    input_cert_group.add_argument('--pai', action='store_true', help='Use input certificate as PAI certificate.')

    g_dev_inst_info = parser.add_argument_group('Device instance information options')
    g_dev_inst_info.add_argument('-v', '--vendor-id', type=any_base_int, help='Vendor id', required=True)
    g_dev_inst_info.add_argument('--vendor-name', help='Vendor name')
    g_dev_inst_info.add_argument('-p', '--product-id', type=any_base_int, help='Product id', required=True)
    g_dev_inst_info.add_argument('--product-name', help='Product name')
    g_dev_inst_info.add_argument('--hw-ver', type=any_base_int, help='Hardware version')
    g_dev_inst_info.add_argument('--hw-ver-str', help='Hardware version string')
    g_dev_inst_info.add_argument('--mfg-date', help='Manufacturing date in format YYYY-MM-DD')
    g_dev_inst_info.add_argument('--serial-num', help='Serial number')
    g_dev_inst_info.add_argument('--enable-rotating-device-id', action='store_true', help='Enable Rotating device id in the generated binaries')
    g_dev_inst_info.add_argument('--rd-id-uid',
                        help='128-bit unique identifier for generating rotating device identifier, provide 32-byte hex string, e.g. "1234567890abcdef1234567890abcdef"')
    product_finish_choices = [finish.name for finish in ProductFinish]
    g_dev_inst_info.add_argument("--product-finish", type=str, choices=product_finish_choices,
                        help='Product finishes choices for product appearance')

    product_color_choices = [color.name for color in ProductColor]
    g_dev_inst_info.add_argument("--product-color", type=str, choices=product_color_choices,
                        help='Product colors choices for product appearance')

    g_dev_inst_info.add_argument("--part-number", type=str, help='human readable product number')


    g_dev_inst = parser.add_argument_group('Device instance options')
    g_dev_inst.add_argument('--calendar-types', nargs='+',
                            help='List of supported calendar types. Supported Calendar Types: Buddhist, Chinese, Coptic, \
                                Ethiopian, Gregorian, Hebrew, Indian, Islamic, Japanese, Korean, Persian, Taiwanese')
    g_dev_inst.add_argument('--locales', nargs='+',
                            help='List of supported locales, Language Tag as defined by BCP47, eg. en-US en-GB')
    g_dev_inst.add_argument('--fixed-labels', nargs='+',
                            help='List of fixed labels, eg: "0/orientation/up" "1/orientation/down" "2/orientation/down"')

    g_dev_inst.add_argument('--supported-modes', type=str, nargs='+', required=False,
                        help='List of supported modes, eg: mode1/label1/ep/"tagValue1\\mfgCode, tagValue2\\mfgCode"  mode2/label2/ep/"tagValue1\\mfgCode, tagValue2\\mfgCode"  mode3/label3/ep/"tagValue1\\mfgCode, tagValue2\\mfgCode"')

    g_basic = parser.add_argument_group('Few more Basic clusters options')
    g_basic.add_argument('--product-label', help='Product label')
    g_basic.add_argument('--product-url', help='Product URL')

    g_extra_info = parser.add_argument_group('Extra information options using csv files')
    g_extra_info.add_argument('--csv', help='CSV file containing the partition schema for extra options. \
            [REF: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/mass_mfg.html#csv-configuration-file]')
    g_extra_info.add_argument('--mcsv', help='Master CSV file containig optional/extra values specified by the user. \
            [REF: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/mass_mfg.html#master-value-csv-file]')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def add_optional_KVs(args):
    # Device instance information
    if args.vendor_id is not None:
        chip_factory_append('vendor-id', 'data', 'u32', args.vendor_id)
    if args.vendor_name is not None:
        chip_factory_append('vendor-name', 'data', 'string', args.vendor_name)
    if args.product_id is not None:
        chip_factory_append('product-id', 'data', 'u32', args.product_id)
    if args.product_name is not None:
        chip_factory_append('product-name', 'data', 'string', args.product_name)
    if args.hw_ver is not None:
        chip_factory_append('hardware-ver', 'data', 'u32', args.hw_ver)
    if args.hw_ver_str is not None:
        chip_factory_append('hw-ver-str', 'data', 'string', args.hw_ver_str)
    if args.mfg_date is not None:
        chip_factory_append('mfg-date', 'data', 'string', args.mfg_date)
    if args.enable_rotating_device_id:
        chip_factory_append('rd-id-uid', 'data', 'hex2bin', args.rd_id_uid)
    if args.product_finish:
        chip_factory_append('product-finish', 'data', 'u32', ProductFinish[args.product_finish].value)
    if args.product_color:
        chip_factory_append('product-color', 'data', 'u32', ProductColor[args.product_color].value)
    if args.part_number:
        chip_factory_append('part-number', 'data', 'string', args.part_number)

    # Add the serial-num
    chip_factory_append('serial-num', 'data', 'string', args.serial_num)

    # Add certificates and keys
    if (args.paa or args.pai) and (not args.dac_in_secure_cert):
        chip_factory_append('dac-cert', 'file', 'binary', None)
        chip_factory_append('dac-key', 'file', 'binary', None)
        chip_factory_append('dac-pub-key', 'file', 'binary', None)
        chip_factory_append('pai-cert', 'file', 'binary', None)

    if not args.enable_dynamic_passcode:
        chip_factory_append('verifier', 'data', 'string', None)

    # Add certificate declaration
    if args.cert_dclrn:
        chip_factory_append('cert-dclrn','file','binary', os.path.relpath(args.cert_dclrn))

    # Add the Keys in csv files
    if args.csv is not None:
        chip_nvs_map_append_config_csv(args.csv)

    # Device information
    if args.calendar_types is not None:
        chip_factory_append('cal-types', 'data', 'u32', calendar_types_to_uint32(args.calendar_types))

    # Supported locale is stored as multiple entries, key format: "locale/<index>, example key: "locale/0"
    if (args.locales is not None):
        chip_factory_append('locale-sz', 'data', 'u32', len(args.locales))
        for i in range(len(args.locales)):
            chip_factory_append('locale/{:x}'.format(i), 'data', 'string', args.locales[i])

    # Each endpoint can contains the fixed lables
    #  - fl-sz/<index>     : number of fixed labels for the endpoint
    #  - fl-k/<ep>/<index> : fixed label key for the endpoint and index
    #  - fl-v/<ep>/<index> : fixed label value for the endpoint and index
    if (args.fixed_labels is not None):
        dict = get_fixed_label_dict(args.fixed_labels)
        for key in dict.keys():
            chip_factory_append('fl-sz/{:x}'.format(int(key)), 'data', 'u32', len(dict[key]))

            for i in range(len(dict[key])):
                entry = dict[key][i]
                chip_factory_append('fl-k/{:x}/{:x}'.format(int(key), i), 'data', 'string', list(entry.keys())[0])
                chip_factory_append('fl-v/{:x}/{:x}'.format(int(key), i), 'data', 'string', list(entry.values())[0])

    # SupportedModes are stored as multiple entries
    #  - sm-sz/<ep>                 : number of supported modes for the endpoint
    #  - sm-label/<ep>/<index>      : supported modes label key for the endpoint and index
    #  - sm-mode/<ep>/<index>       : supported modes mode key for the endpoint and index
    #  - sm-st-sz/<ep>/<index>      : supported modes SemanticTag key for the endpoint and index
    #  - st-v/<ep>/<index>/<ind>    : semantic tag value key for the endpoint and index and ind
    #  - st-mfg/<ep>/<index>/<ind>  : semantic tag mfg code key for the endpoint and index and ind
    if (args.supported_modes is not None):
        dictionary = get_supported_modes_dict(args.supported_modes)
        for ep in dictionary.keys():
            chip_factory_append('sm-sz/{:x}'.format(int(ep)), 'data', 'u32', len(dictionary[ep]))

            for i in range(len(dictionary[ep])):
                item = dictionary[ep][i]

                chip_factory_append('sm-label/{:x}/{:x}'.format(int(ep), i), 'data', 'string', item["Label"])
                chip_factory_append('sm-mode/{:x}/{:x}'.format(int(ep), i), 'data', 'u32', item["Mode"])
                chip_factory_append('sm-st-sz/{:x}/{:x}'.format(int(ep), i), 'data', 'u32', len(item["Semantic_Tag"]))

                for j in range(len(item["Semantic_Tag"])):
                    entry = item["Semantic_Tag"][j]

                    _value = {
                        'type': 'data',
                        'encoding': 'u32',
                        'value': entry["value"]
                    }
                    _mfg_code = {
                        'type': 'data',
                        'encoding': 'u32',
                        'value': entry["mfgCode"]
                    }

                    chip_factory_append('st-v/{:x}/{:x}/{:x}'.format(int(ep), i, j), 'data', 'u32', entry["value"])
                    chip_factory_append('st-mfg/{:x}/{:x}/{:x}'.format(int(ep), i, j), 'data', 'u32', entry["mfgCode"])

    # Keys from basic clusters
    if args.product_label is not None:
        chip_factory_append('product-label', 'data', 'string', args.product_label)
    if args.product_url is not None:
        chip_factory_append('product-url', 'data', 'string', args.product_url)

def main_internal(args):
    logging.basicConfig(format='[%(asctime)s] [%(levelname)7s] - %(message)s', level=__LOG_LEVELS__[args.log_level])
    validate_args(args)
    validate_certificates(args)
    setup_out_dirs(args.vendor_id, args.product_id, args.count, args.outdir, args.dac_cert)
    add_optional_KVs(args)
    generate_passcodes_and_discriminators(args)
    write_csv_files(args)
    if args.paa or args.pai:
        setup_root_certs(args)
    write_per_device_unique_data(args)
    generate_partitions('matter_partition', args.size, args.encrypt, args.generate_bin)
    organize_output_files('matter_partition', args)
    generate_summary(args)

def main():
    args = get_args()
    main_internal(args)

if __name__ == "__main__":
    main()
