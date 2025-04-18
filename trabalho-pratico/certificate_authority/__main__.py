import argparse
import pathlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID


def generate_ca_certificate(output_dir: str) -> None:
    """Generate a Certificate Authority (CA) certificate and private key."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSI VAULT SERVICE"),
            x509.NameAttribute(NameOID.COMMON_NAME, "VAULT_CA"),
            x509.NameAttribute(NameOID.PSEUDONYM, "VAULT_CA"),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.not_valid_before(datetime.now(timezone.utc))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    certificate = builder.sign(key, algorithm=hashes.SHA256())

    # Create output directories if they don't exist
    cert_dir = pathlib.Path(output_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)

    cert_path = cert_dir / "VAULT_CA.crt"

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"✅ CA certificate successfully generated and saved to {cert_path}")

    return certificate, key


def generate_server_certificate(
    ca_certificate, ca_private_key, server_name: str, output_dir: str
) -> None:
    """Generate a server certificate signed by the CA."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSI VAULT SERVICE"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI VAULT SERVICE"),
            x509.NameAttribute(NameOID.COMMON_NAME, server_name),
            x509.NameAttribute(NameOID.PSEUDONYM, server_name),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.not_valid_before(datetime.now(timezone.utc))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    certificate = builder.sign(ca_private_key, algorithm=hashes.SHA256())
    # Create a PKCS12 file
    p12 = pkcs12.serialize_key_and_certificates(
        server_name.encode(), key, certificate, [ca_certificate], NoEncryption()
    )
    # Save the PKCS12 file
    server_cert_path = pathlib.Path(output_dir) / f"{server_name}.p12"

    with open(server_cert_path, "wb") as f:
        f.write(p12)
    print(f"✅ Certificado guardado em: {server_cert_path}")


def generate_client_certificate(
    ca_certificate, ca_private_key, client_name: str, output_dir: str
) -> None:
    """Generate a client certificate signed by the CA."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSI VAULT SERVICE"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI VAULT SERVICE"),
            x509.NameAttribute(NameOID.COMMON_NAME, client_name),
            x509.NameAttribute(NameOID.PSEUDONYM, client_name),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.not_valid_before(datetime.now(timezone.utc))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    certificate = builder.sign(ca_private_key, algorithm=hashes.SHA256())

    # Create a PKCS12 file
    p12 = pkcs12.serialize_key_and_certificates(
        client_name.encode(), key, certificate, [ca_certificate], NoEncryption()
    )
    # Save the PKCS12 file
    client_cert_path = pathlib.Path(output_dir) / f"{client_name}.p12"
    with open(client_cert_path, "wb") as f:
        f.write(p12)
    print(f"✅ Certificado guardado em: {client_cert_path}")


def create_certificates(output_dir: str, server_count: int, client_count: int) -> None:
    """Create CA, servers and clients certificates."""
    # Generate CA certificate and key
    ca_cert, ca_key = generate_ca_certificate(output_dir)

    # Create server certificates
    if server_count == 1:
        generate_server_certificate(ca_cert, ca_key, "VAULT_SERVER", output_dir)
    else:
        for i in range(server_count):
            generate_server_certificate(
                ca_cert, ca_key, f"VAULT_SERVER_{i+1}", output_dir
            )

    # Create client certificates
    for i in range(client_count):
        generate_client_certificate(ca_cert, ca_key, f"VAULT_CLI{i+1}", output_dir)

    print("✅ All certificates created successfully!")


def main():
    parser = argparse.ArgumentParser(
        description="Certificate Authority Management Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create certificates")
    create_parser.add_argument(
        "-s",
        "--server",
        type=int,
        required=True,
        help="Number of server certificates to create",
    )
    create_parser.add_argument(
        "-c",
        "--client",
        type=int,
        required=True,
        help="Number of client certificates to create",
    )
    create_parser.add_argument(
        "-o", "--output", required=True, help="Output directory for certificates"
    )

    args = parser.parse_args()

    if args.command == "create":
        create_certificates(args.output, args.server, args.client)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
