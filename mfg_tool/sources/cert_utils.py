#!/usr/bin/env python3

# Copyright 2024 Espressif Systems (Shanghai) PTE LTD
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
contains utility functions for generating csr, build certificates, certs/keys conversion etc.
"""
import logging
from typing import Optional
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.exceptions import InvalidSignature
from utils import VERIFY_OR_EXIT, VERIFY_OR_RAISE

# CHIP OID for vendor id
VENDOR_ID_OID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.1')

# CHIP OID for product id
PRODUCT_ID_OID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.2')

VALID_DAYS = 365 * 100

CERTIFICATE_VERSION = x509.Version.v3
SIGNATURE_ALGORITHM = "ecdsa-with-SHA256"

def save_to_file(file_name, file_data):
    """
    Save filedata to file
    Args:
    file_name (str): file name for the file.
    file_data (bytes): file data to store in file.
    """
    with open(file_name, 'wb') as file:
        file.write(file_data)

def chip_gen_ec_key():
    """
    Generate EC private key.
    Returns:
        ec.EllipticCurvePrivateKey: Generated private key object.
    """
    return ec.generate_private_key(ec.SECP256R1())

def load_cert_from_file(cert_file):
    """
    Load an X.509 certificate from file in PEM or DER format.
    Args:
        cert_file (str): Path to the certificate file.
    Returns:
        x509.Certificate: Parsed certificate object in PEM or DER format.
    Raises:
        ValueError: If the certificate format is invalid or unsupported.
    """
    with open(cert_file, 'rb') as file:
        cert_data = file.read()

    # Attempt to load as PEM first, then fallback to DER
    for loader in (load_pem_x509_certificate, load_der_x509_certificate):
        try:
            return loader(cert_data)
        except ValueError:
            continue

    raise ValueError("Invalid certificate format. Supported formats: PEM, DER.")

def load_key_from_file(key_file):
    """
    Load a private key from file in PEM or DER format.
    Args:
        key_file (str): Path to the private key file.
    Returns:
        ec.EllipticCurvePrivateKey: Parsed private key object in PEM or DER format.
    Raises:
        ValueError: If the key format is invalid or unsupported.
    """
    with open(key_file, 'rb') as file:
        key_data = file.read()

    # Attempt to load as PEM first, then fallback to DER
    for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        try:
            return loader(key_data, password=None)
        except ValueError:
            continue

    raise ValueError("Invalid key format or unsupported key type. Supported formats: PEM, DER.")

def convert_x509_cert_from_pem_to_der(pem_file, out_der_file):
    """
    Convert an X509 certificate from PEM to DER format.
    Args:
        pem_file (str): Path to the PEM file.
        out_der_file (str): Output path for the DER file.
    """
    cert = load_cert_from_file(pem_file)
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    save_to_file(out_der_file, der_cert)

def convert_private_key_from_pem_to_der(pem_file, out_der_file):
    """
    Convert a private key from PEM to DER format.
    Args:
        pem_file (str): Path to the PEM file.
        out_der_file (str): Output path for the DER file.
    """
    key = load_key_from_file(pem_file)
    der_key = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_to_file(out_der_file, der_key)

def store_keypair_as_raw(pem_file, out_privkey_bin, out_pubkey_bin):
    """
    Generate a binary format key pair from a PEM file.
    Args:
        pem_file (str): Path to the PEM file containing the private key.
        out_privkey_bin (str): Output path for the private key in binary format.
        out_pubkey_bin (str): Output path for the public key in binary format.
    """
    key = load_key_from_file(pem_file)
    priv_val = key.private_numbers().private_value
    pub_numbers = key.public_key().public_numbers()

    priv_key_data = priv_val.to_bytes(32, byteorder='big')
    save_to_file(out_privkey_bin, priv_key_data)

    with open(out_pubkey_bin, 'wb') as pub_file:
        pub_file.write(b'\x04')
        pub_file.write(pub_numbers.x.to_bytes(32, byteorder='big'))
        pub_file.write(pub_numbers.y.to_bytes(32, byteorder='big'))

def extract_matter_rdn(subject, oid):
    """
    Extract the value of a custom OID from a certificate.
    Args:
        subject (x509.Name): Subject from which to extract the OID value.
        oid (x509.ObjectIdentifier): OID to extract.
    Returns:
        str: Extracted OID value or None if not found.
    """
    try:
        return subject.get_attributes_for_oid(oid)[0].value
    except IndexError:
        return None

def extract_pid(subject):
    """
    Extract the Product ID (PID) from a certificate's subject.
    Args:
        subject (x509.Name): Subject from which to extract the PID.
    Returns:
        str: Extracted PID or None if not found.
    """
    return extract_matter_rdn(subject, PRODUCT_ID_OID)

def extract_vid(subject):
    """
    Extract the Vendor ID (VID) from a certificate's subject.
    Args:
        subject (x509.Name): Subject from which to extract the VID.
    Returns:
        str: Extracted VID or None if not found.
    """
    return extract_matter_rdn(subject, VENDOR_ID_OID)

def extract_common_name(subject) -> Optional[str]:
    """
    Extract the Common Name (CN) from a certificate's subject.
    Args:
        subject (x509.Name): Subject from which to extract the CN.
    Returns:
        str: Extracted CN or None if not found.
    """
    return extract_matter_rdn(subject, x509.NameOID.COMMON_NAME)

def generate_cert_validity(valid_from, lifetime):
    """
    Generate a certificate validity period.
    Args:
        valid_from (str): Start date for the certificate validity period in ISO 8601 format ("YYYY-MM-DDTHH:MM:SS").
        lifetime (int): Lifetime of the certificate in days.
    Returns:
        tuple: Tuple containing the start and end dates of the certificate validity period.
    """
    nvb_time = datetime.utcnow()
    nva_time = nvb_time + timedelta(days=VALID_DAYS)
    if valid_from:
        nvb_time = datetime.strptime(str(valid_from), "%Y-%m-%dT%H:%M:%S")
    if lifetime:
        nva_time = nvb_time + timedelta(days=lifetime)
    return nvb_time, nva_time

def generate_cert_subject(vendor_id, product_id, common_name):
    """
    Generate a certificate subject.
    Args:
        vendor_id (str): Vendor ID
        product_id (str): Product ID
        common_name (str): Common Name
    Returns:
        x509.Name: Generated certificate subject.
    """
    x509_attrs = []
    x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    x509_attrs.append(x509.NameAttribute(VENDOR_ID_OID, vendor_id.zfill(4)))
    x509_attrs.append(x509.NameAttribute(PRODUCT_ID_OID, product_id.zfill(4)))
    return x509.Name(x509_attrs)

def build_certificate(vendor_id:str, product_id:str, ca_cert_file: str, ca_privkey_file: str, out_cert_file: str, out_key_file: str, is_pai: bool, common_name: str, valid_from=None, lifetime=None):
    """
    Build a certificate for a Matter device.

    Args:
        vendor_id (str): vendor id
        product_id (str): product id
        ca_cert_file (str): Path to the CA certificate file used for signing.
        ca_privkey_file (str): Path to the CA private key file used for signing.
        out_cert_file (str): Path to save the generated certificate.
        out_key_file (str): Path to save the private key for the certificate.
        is_pai (bool): Indicates if the certificate is a Product Attestation Intermediate (PAI) certificate.
        common_name (str): Common Name for the certificate subject.
        valid_from (str, optional): Start date for the certificate validity period in ISO 8601 format ("YYYY-MM-DDTHH:MM:SS").
            Defaults to None, in which case the current date is used.
        lifetime (int, optional): Lifetime of the certificate in days. Defaults to None, in which case a default period (e.g., 100 years) is used.

    Returns:
        None: Saves the generated certificate and key to the specified files.
    """
    if not ca_cert_file or not ca_privkey_file:
        raise ValueError("CA key and certificate cannot be None.")

    try:
        # Load CA certificate and key
        ca_cert = load_cert_from_file(ca_cert_file)
        ca_key = load_key_from_file(ca_privkey_file)

        # Generate a new private key for the device certificate
        private_key = chip_gen_ec_key()
        public_key = private_key.public_key()

        # Build subject attributes
        cert_subject = generate_cert_subject(vendor_id, product_id, common_name)

        nvb_time, nva_time = generate_cert_validity(valid_from, lifetime)

        # Build certificate
        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(ca_cert.subject)
        cert = cert.public_key(public_key)
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(nvb_time)
        cert = cert.not_valid_after(nva_time)

        # Extensions for PAI certificate
        if is_pai:
            cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                    key_encipherment=False, data_encipherment=False,
                                                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                    encipher_only=False, decipher_only=False), critical=True)
        # Extensions for DAC certificate
        else:
            cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                    key_encipherment=False, data_encipherment=False,
                                                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                                                    encipher_only=False, decipher_only=False), critical=True)

        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)

        # Sign the certificate
        signed_cert = cert.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # Save the certificate to a file
        certificate_pem = signed_cert.public_bytes(serialization.Encoding.PEM)
        save_to_file(out_cert_file, certificate_pem)

        # Save the private key to a file
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        save_to_file(out_key_file, private_key_pem)

    except Exception as e:
        raise RuntimeError(f"Failed to build certificate: {e}")

def validate_certificate_validity(valid_from: str, lifetime: int, cert_file: str) -> bool:
    """
    Validate the certificate validity.
    Args:
        valid_from (str): Start date for the certificate validity period in ISO 8601 format ("YYYY-MM-DDTHH:MM:SS").
        lifetime (int): Lifetime of the certificate in days.
        cert_file (str): Path to the certificate file.
    Returns:
        bool: True if the certificate validity is valid, False otherwise.
    """
    try:
        cert = load_cert_from_file(cert_file)
        nvb_time, nva_time = generate_cert_validity(valid_from, lifetime)
        VERIFY_OR_RAISE(cert.not_valid_before <= nvb_time <= cert.not_valid_after,
                       f"Specified start date ({nvb_time}) is outside certificate's validity period ({cert.not_valid_before} to {cert.not_valid_after})")
        VERIFY_OR_RAISE(cert.not_valid_before <= nva_time <= cert.not_valid_after,
                        f"Specified end date based on lifetime ({nva_time}) is outside certificate's validity period ({cert.not_valid_before} to {cert.not_valid_after})")
        return True
    except Exception as e:
        logging.error(f"Certificate validity validation failed for {cert_file}: {str(e)}")
        return False

def validate_vid_pid_with_pai_cert(vid: int, pid: int, pai_cert_file: str) -> bool:
    """
    Validate input VID and PID with the PAI certificate.
    Args:
        vid (int): Input Vendor ID
        pid (int): Input Product ID
        pai_cert_file (str): Input PAI certificate file
    Returns:
        bool: True if the VID and PID match the VID and PID in the PAI certificate, False otherwise.
    Raises:
        ValueError: If the certificate is missing required VID/PID or values don't match.
    """
    try:
        cert = load_cert_from_file(pai_cert_file)
        extracted_vid = extract_vid(cert.subject)
        extracted_pid = extract_pid(cert.subject)

        VERIFY_OR_RAISE(extracted_vid, "Missing VID in PAI certificate")
        try:
            extracted_vid_int = int(extracted_vid, 16)
            VERIFY_OR_RAISE(extracted_vid_int == vid,
                           f"VID: {extracted_vid_int} (0x{extracted_vid}) in PAI certificate does not match input VID: {vid} (0x{vid:04x})")
        except ValueError:
            VERIFY_OR_RAISE(False, f"Invalid VID format in certificate: {extracted_vid}")

        if extracted_pid is not None:
            try:
                extracted_pid_int = int(extracted_pid, 16)
                VERIFY_OR_RAISE(extracted_pid_int == pid,
                               f"PID: {extracted_pid_int} (0x{extracted_pid}) in PAI certificate does not match input PID: {pid} (0x{pid:04x})")
            except ValueError:
                VERIFY_OR_RAISE(False, f"Invalid PID format in certificate: {extracted_pid}")
        return True
    except Exception as e:
        logging.error(f"VID/PID validation failed: {str(e)}")
        return False

def validate_dac_cert(dac_cert_file: str) -> bool:
    """
    Validate the DAC certificate.
    Args:
        dac_cert_file (str): Path to the DAC certificate file.
    Returns:
        bool: True if the DAC certificate is valid, False otherwise.
    """
    try:
        dac_cert = load_cert_from_file(dac_cert_file)

        VERIFY_OR_RAISE(dac_cert.version == CERTIFICATE_VERSION,
                       f"DAC certificate version must be {CERTIFICATE_VERSION}, got {dac_cert.version}")
        VERIFY_OR_RAISE(dac_cert.signature_algorithm_oid._name == SIGNATURE_ALGORITHM,
                       f"DAC certificate signature algorithm must be {SIGNATURE_ALGORITHM}, got {dac_cert.signature_algorithm_oid._name}")

        vendor_id = extract_vid(dac_cert.subject)
        product_id = extract_pid(dac_cert.subject)
        VERIFY_OR_RAISE(vendor_id and product_id, "Missing VID or PID in DAC certificate")


        issuer_vid = extract_vid(dac_cert.issuer)
        issuer_pid = extract_pid(dac_cert.issuer)
        VERIFY_OR_RAISE(issuer_vid, "Missing VID in DAC certificate issuer")
        VERIFY_OR_RAISE(issuer_vid == vendor_id,
                       f"DAC certificate issuer's VID '{issuer_vid}' must match the certificate's VID '{vendor_id}'")
        if issuer_pid is not None:
            VERIFY_OR_RAISE(issuer_pid == product_id,
                           f"DAC certificate issuer's PID '{issuer_pid}' must match the certificate's PID '{product_id}'")

        subject_public_key_info = dac_cert.public_key().curve.name
        VERIFY_OR_RAISE(subject_public_key_info == "secp256r1",
                       f"The algorithm in subjectPublicKeyInfo field must be prime256v1, got {subject_public_key_info}")

        try:
            basic_constraints = dac_cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            VERIFY_OR_RAISE(basic_constraints.critical, "DAC Basic Constraints extension must be marked as critical")
            VERIFY_OR_RAISE(not basic_constraints.value.ca, "DAC must not be a CA certificate")

            key_usage = dac_cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            VERIFY_OR_RAISE(key_usage.critical, "DAC Key Usage extension must be marked as critical")
            VERIFY_OR_RAISE(key_usage.value.digital_signature, "DAC must have digital signature usage enabled")
            VERIFY_OR_RAISE(not (key_usage.value.content_commitment or
                                 key_usage.value.key_encipherment or
                                 key_usage.value.data_encipherment or
                                 key_usage.value.key_agreement or
                                 key_usage.value.crl_sign or
                                 key_usage.value.key_cert_sign), "DAC must not have unsupported key usage extensions")

            subject_key_id = dac_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            authority_key_id = dac_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            VERIFY_OR_RAISE(subject_key_id, "DAC missing Subject Key Identifier extension")
            VERIFY_OR_RAISE(authority_key_id, "DAC missing Authority Key Identifier extension")
        except x509.ExtensionNotFound as e:
            logging.error(f"DAC missing required extension: {str(e)}")
            return False
        return True

    except Exception as e:
        logging.error(f"DAC certificate validation failed: {str(e)}")
        return False

def validate_pai_cert(pai_cert_file: str) -> bool:
    """
    Validate the PAI certificate.
    Args:
        pai_cert_file (str): Path to the PAI certificate file.
    Returns:
        bool: True if the PAI certificate is valid, False otherwise.
    """
    try:
        pai_cert = load_cert_from_file(pai_cert_file)

        VERIFY_OR_RAISE(pai_cert.version == CERTIFICATE_VERSION,
                       f"PAI certificate version must be {CERTIFICATE_VERSION}, got {pai_cert.version}")
        VERIFY_OR_RAISE(pai_cert.signature_algorithm_oid._name == SIGNATURE_ALGORITHM,
                       f"PAI certificate signature algorithm must be {SIGNATURE_ALGORITHM}, got {pai_cert.signature_algorithm_oid._name}")

        vendor_id = extract_vid(pai_cert.subject)
        VERIFY_OR_RAISE(vendor_id, "Missing VID in PAI certificate")

        issuer_vid = extract_vid(pai_cert.issuer)
        if issuer_vid is not None:
            VERIFY_OR_RAISE(issuer_vid == vendor_id,
                           f"PAI certificate issuer's VID '{issuer_vid}' must match the certificate's VID '{vendor_id}'")

        subject_public_key_info = pai_cert.public_key().curve.name
        VERIFY_OR_RAISE(subject_public_key_info == "secp256r1",
                       f"The algorithm in subjectPublicKeyInfo field must be prime256v1, got {subject_public_key_info}")

        try:
            basic_constraints = pai_cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            VERIFY_OR_RAISE(basic_constraints.critical, "PAI Basic Constraints extension must be marked as critical")
            VERIFY_OR_RAISE(basic_constraints.value.ca, "PAI must be a CA certificate")
            VERIFY_OR_RAISE(basic_constraints.value.path_length == 0,
                           f"PAI path length must be 0, got {basic_constraints.value.path_length}")

            key_usage = pai_cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            VERIFY_OR_RAISE(key_usage.critical, "PAI Key Usage extension must be marked as critical")
            VERIFY_OR_RAISE(key_usage.value.key_cert_sign, "PAI must have keyCertSign usage enabled")
            VERIFY_OR_RAISE(key_usage.value.crl_sign, "PAI must have cRLSign usage enabled")
            VERIFY_OR_RAISE(not (key_usage.value.content_commitment or
                                 key_usage.value.key_agreement or
                                 key_usage.value.key_encipherment or
                                 key_usage.value.data_encipherment), "PAI must not have unsupported key usage extensions")

            subject_key_id = pai_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            authority_key_id = pai_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            VERIFY_OR_RAISE(subject_key_id, "PAI missing Subject Key Identifier extension")
            VERIFY_OR_RAISE(authority_key_id, "PAI missing Authority Key Identifier extension")
        except x509.ExtensionNotFound as e:
            logging.error(f"PAI missing required extension: {str(e)}")
            return False
        return True
    except Exception as e:
        logging.error(f"PAI certificate validation failed: {str(e)}")
        return False

def validate_paa_cert(paa_cert_file: str) -> bool:
    """
    Validate the PAA certificate.
    Args:
        paa_cert_file (str): Path to the PAA certificate file.
    Returns:
        bool: True if the PAA certificate is valid, False otherwise.
    """
    try:
        paa_cert = load_cert_from_file(paa_cert_file)

        VERIFY_OR_RAISE(paa_cert.version == CERTIFICATE_VERSION,
                       f"PAA certificate version must be {CERTIFICATE_VERSION}, got {paa_cert.version}")
        VERIFY_OR_RAISE(paa_cert.signature_algorithm_oid._name == SIGNATURE_ALGORITHM,
                       f"PAA certificate signature algorithm must be {SIGNATURE_ALGORITHM}, got {paa_cert.signature_algorithm_oid._name}")

        # Self-signed check
        VERIFY_OR_RAISE(paa_cert.subject == paa_cert.issuer, "PAA must be self-signed")

        pid = extract_pid(paa_cert.subject)
        VERIFY_OR_RAISE(pid is None, "PAA must not include a Product ID (PID)")

        subject_public_key_info = paa_cert.public_key().curve.name
        VERIFY_OR_RAISE(subject_public_key_info == "secp256r1",
                       f"The algorithm in subjectPublicKeyInfo field must be prime256v1, got {subject_public_key_info}")

        try:
            basic_constraints = paa_cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            VERIFY_OR_RAISE(basic_constraints.critical, "PAA Basic Constraints extension must be marked as critical")
            VERIFY_OR_RAISE(basic_constraints.value.ca, "PAA must be a CA certificate")
            if basic_constraints.value.path_length is not None:
                VERIFY_OR_RAISE(basic_constraints.value.path_length == 1,
                               f"PAA path length must be 1, got {basic_constraints.value.path_length}")

            key_usage = paa_cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            VERIFY_OR_RAISE(key_usage.critical, "PAA Key Usage extension must be marked as critical")
            VERIFY_OR_RAISE(key_usage.value.key_cert_sign, "PAA must have keyCertSign usage enabled")
            VERIFY_OR_RAISE(key_usage.value.crl_sign, "PAA must have cRLSign usage enabled")
            VERIFY_OR_RAISE(not (key_usage.value.content_commitment or
                                 key_usage.value.key_agreement or
                                 key_usage.value.key_encipherment or
                                 key_usage.value.data_encipherment), "PAA must not have unsupported key usage extensions")

            subject_key_id = paa_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            VERIFY_OR_RAISE(subject_key_id, "PAA missing Subject Key Identifier extension")
        except x509.ExtensionNotFound:
            logging.error("PAA missing extension")
            return False
        return True

    except Exception as e:
        logging.error(f"PAA certificate validation failed: {str(e)}")
        return False

def validate_certificate_chain(cert_file: str, issuer_cert_file: str) -> bool:
    """
    Validate the certificate chain.
    Args:
        cert_file (str): Path to the certificate file.
        issuer_cert_file (str): Path to the issuer certificate file.
    Returns:
        bool: True if the certificate chain is valid, False otherwise.
    """
    try:
        cert = load_cert_from_file(cert_file)
        issuer_cert = load_cert_from_file(issuer_cert_file)

        # Check issuer-subject chaining
        VERIFY_OR_RAISE(cert.issuer == issuer_cert.subject,
                       f"Issuer-subject mismatch: {cert.issuer} != {issuer_cert.subject}")

        # Check certificate validity periods
        VERIFY_OR_RAISE(issuer_cert.not_valid_before <= cert.not_valid_before <= issuer_cert.not_valid_after,
                       f"Certificate is not currently valid. Valid from {issuer_cert.not_valid_before} to {issuer_cert.not_valid_after}")
        VERIFY_OR_RAISE(issuer_cert.not_valid_before <= cert.not_valid_after <= issuer_cert.not_valid_after,
                       f"Certificate is not currently valid. Valid from {issuer_cert.not_valid_before} to {issuer_cert.not_valid_after}")

        # Check for authority key identifier and subject key identifier
        try:
            cert_authority_key_id = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            issuer_cert_subject_key_id = issuer_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            VERIFY_OR_RAISE(cert_authority_key_id, "Certificate missing Authority Key Identifier extension")
            VERIFY_OR_RAISE(issuer_cert_subject_key_id, "Issuer certificate missing Subject Key Identifier extension")
            VERIFY_OR_RAISE(cert_authority_key_id.value.key_identifier == issuer_cert_subject_key_id.value.digest,
                           "Certificate Authority Key Identifier and Issuer certificate Subject Key Identifier must match")
        except x509.ExtensionNotFound as e:
            logging.error(f"Missing required key identifier extension: {str(e)}")
            return False

        # Verify certificate signature using issuer's public key
        try:
            issuer_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        except Exception as e:
            logging.error(f"Signature verification failed: {str(e)}")
            return False

        try:
            issuer_constraints = issuer_cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            )
            VERIFY_OR_RAISE(issuer_constraints.value.ca, "Issuer certificate is not a CA")
        except Exception as e:
            logging.error(f"Failed to check issuer basic constraints: {str(e)}")
            return False

        return True

    except Exception as e:
        logging.error(f"Certificate chain validation failed: {str(e)}")
        return False

def verify_certificate_private_key(cert_file: str, private_key_file: str) -> bool:
    """
    Validate the input certificate and private key provided through arguments.

    Args:
        cert_file (str): Path to the certificate file.
        private_key_file (str): Path to the private key file.
    Returns:
        bool: True if the private key matches the certificate, False otherwise.
    """
    try:
        cert = load_cert_from_file(cert_file)
        cert_public_key = cert.public_key()
        private_key = load_key_from_file(private_key_file)

        # Verify key types are compatible
        VERIFY_OR_RAISE(isinstance(cert_public_key, ec.EllipticCurvePublicKey), "Certificate public key is not an elliptic curve key")
        VERIFY_OR_RAISE(isinstance(private_key, ec.EllipticCurvePrivateKey), "Private key is not an elliptic curve key")

        # Verify key curves match
        VERIFY_OR_RAISE(cert_public_key.curve.name == private_key.curve.name,
                       f"Key curve mismatch: cert uses {cert_public_key.curve.name}, private key uses {private_key.curve.name}")

        # Test message to sign and verify
        test_message = b"Test message for key validation"

        # Sign with private key
        signature = private_key.sign(
            test_message,
            ec.ECDSA(hashes.SHA256())
        )

        # Verify with certificate's public key
        try:
            cert_public_key.verify(
                signature,
                test_message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            logging.error("Signature verification failed - private key does not correspond to certificate")
            return False

    except Exception as e:
        logging.error(f"Failed to verify certificate private key: {str(e)}")
        return False

def validate_certificates(args):
    if args.pai:
        VERIFY_OR_EXIT(args.cert, "PAI certificate is required")
        VERIFY_OR_EXIT(validate_pai_cert(args.cert), "PAI certificate is not valid")
        # In case of dac certificate and dac privatekey as a input pai certificate private key can be optional
        if args.key:
            VERIFY_OR_EXIT(verify_certificate_private_key(args.cert, args.key), "PAI certificate and private key do not match")
        VERIFY_OR_EXIT(validate_vid_pid_with_pai_cert(args.vendor_id, args.product_id, args.cert), "PAI certificate VID and PID do not match input VID and PID")

    if args.paa:
        VERIFY_OR_EXIT(args.cert, "PAA certificate is required")
        VERIFY_OR_EXIT(validate_paa_cert(args.cert), "PAA certificate is not valid")
        VERIFY_OR_EXIT(args.key, "PAA private key is required")
        VERIFY_OR_EXIT(verify_certificate_private_key(args.cert, args.key), "PAA certificate and private key do not match")

    if args.dac_cert:
        VERIFY_OR_EXIT(args.dac_key, "DAC private key is required")
        VERIFY_OR_EXIT(args.cert, "PAI certificate is required")
        VERIFY_OR_EXIT(validate_dac_cert(args.dac_cert), "DAC certificate is not valid")
        VERIFY_OR_EXIT(verify_certificate_private_key(args.dac_cert, args.dac_key), "DAC certificate and private key do not match")
        VERIFY_OR_EXIT(validate_certificate_chain(args.dac_cert, args.cert), "DAC certificate chain is not valid")

    if (args.valid_from or args.lifetime) and args.cert:
        VERIFY_OR_EXIT(validate_certificate_validity(args.valid_from, args.lifetime, args.cert),
                      f"{'PAA' if args.paa else 'PAI'} Certificate validity period is outside the specified parameters (from: {args.valid_from}, lifetime: {args.lifetime} days)")
        if args.dac_cert:
            VERIFY_OR_EXIT(validate_certificate_validity(args.valid_from, args.lifetime, args.dac_cert),
                          f"DAC certificate validity period is outside the specified parameters (from: {args.valid_from}, lifetime: {args.lifetime} days)")
