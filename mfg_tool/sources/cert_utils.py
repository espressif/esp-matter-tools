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
import datetime
from typing import Optional
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# CHIP OID for vendor id
VENDOR_ID_OID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.1')

# CHIP OID for product id
PRODUCT_ID_OID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.2')

VALID_DAYS = 365 * 100

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

def extract_matter_rdn(cert, oid):
    """
    Extract the value of a custom OID from a certificate.
    Args:
        cert (x509.Certificate): Certificate from which to extract the OID value.
        oid (x509.ObjectIdentifier): OID to extract.
    Returns:
        str: Extracted OID value or None if not found.
    """
    try:
        return cert.subject.get_attributes_for_oid(oid)[0].value
    except IndexError:
        return None

def extract_pid(cert):
    """
    Extract the Product ID (PID) from a certificate's subject.
    Args:
        cert (x509.Certificate): Certificate from which to extract the PID.
    Returns:
        str: Extracted PID or None if not found.
    """
    return extract_matter_rdn(cert, PRODUCT_ID_OID)

def extract_vid(cert):
    """
    Extract the Vendor ID (VID) from a certificate's subject.
    Args:
        cert (x509.Certificate): Certificate from which to extract the VID.
    Returns:
        str: Extracted VID or None if not found.
    """
    return extract_matter_rdn(cert, VENDOR_ID_OID)

def extract_common_name(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the Common Name (CN) from a certificate's subject.
    Args:
        cert (x509.Certificate): Certificate from which to extract the CN.
    Returns:
        str: Extracted CN or None if not found.
    """
    return extract_matter_rdn(cert, x509.NameOID.COMMON_NAME)

def generate_cert_subject(vendor_id, product_id, common_name):
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

        # Define validity period
        nvb_time = datetime.utcnow()
        nva_time = nvb_time + timedelta(days=VALID_DAYS)  # Default to 100 years
        if valid_from:
            nvb_time = datetime.strptime(str(valid_from), "%Y-%m-%dT%H:%M:%S")
        if lifetime:
            nva_time = nvb_time + timedelta(days=lifetime)

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
