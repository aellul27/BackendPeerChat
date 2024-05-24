from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import *

def create_user_csr(username):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{username}"),
            # Add other attributes as needed (e.g., organization, country, etc.)
        ])
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.PEM)

def create_user_cert(csr):
    # Load your root CA certificate
    with open('/private/ca/rootCACert.pem', 'rb') as root_ca_file:
        root_ca_cert = x509.load_pem_x509_certificate(root_ca_file.read(), default_backend())

    # Load your root CA private key
    with open('/private/ca/rootCAKey.pem', 'rb') as root_ca_key_file:
        root_ca_key = serialization.load_pem_private_key(root_ca_key_file.read(), password=None,
                                                         backend=default_backend())
    user_csr = x509.load_pem_x509_csr(csr)
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(user_csr.subject)
        .issuer_name(root_ca_cert.subject)
        .public_key(user_csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_ca_key, hashes.SHA256(), default_backend())
    )

    return user_cert.public_bytes(serialization.Encoding.PEM)
