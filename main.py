from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import ssl
import socket
from datetime import datetime
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

app = FastAPI()

class SSLRequest(BaseModel):
    urls: List[str]

@app.get("/health")
async def health():
    return {"status": "ok"}

def get_ssl_info(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert()
            cipher = ssock.cipher()  # (cipher_name, protocol_version, secret_bits)
            session_reused = getattr(ssock, 'session_reused', None)
            # peer_cert_chain is not directly available in stdlib, so skip for now
            return cert, der_cert, ssock.version(), ssock.getpeername()[0], cipher, session_reused


def parse_cert(cert, der_cert, version, resolved_ip, cipher, session_reused):
    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject.get('commonName', '')
    issuer = dict(x[0] for x in cert['issuer'])
    issuer_c = issuer.get('countryName', '')
    issuer_o = issuer.get('organizationName', '')
    valid_from = cert['notBefore']
    valid_till = cert['notAfter']
    valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
    valid_till_dt = datetime.strptime(valid_till, "%b %d %H:%M:%S %Y %Z")
    validity_days = (valid_till_dt - valid_from_dt).days
    days_left = (valid_till_dt - datetime.utcnow()).days
    cert_exp = days_left < 0
    cert_valid = not cert_exp

    # Parse with cryptography for serial, sha1, alg, and more
    x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
    cert_sn = hex(x509_cert.serial_number)
    cert_sha1 = x509_cert.fingerprint(hashes.SHA1()).hex()
    cert_alg = x509_cert.signature_hash_algorithm.name
    signature_algorithm_oid = x509_cert.signature_algorithm_oid.dotted_string
    public_key = x509_cert.public_key()
    public_key_algorithm = public_key.__class__.__name__
    public_key_size = getattr(public_key, 'key_size', None)
    issuer_full = x509_cert.issuer.rfc4514_string()
    subject_full = x509_cert.subject.rfc4514_string()
    is_self_signed = x509_cert.issuer == x509_cert.subject
    # Extensions
    extensions = {}
    for ext in x509_cert.extensions:
        try:
            extensions[ext.oid._name] = str(ext.value)
        except Exception:
            extensions[str(ext.oid)] = str(ext.value)
    # Subject Alternative Names
    try:
        san = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        subject_alt_names = san.value.get_values_for_type(x509.DNSName)
    except Exception:
        subject_alt_names = []

    return {
        "host": subject.get('commonName', ''),
        "resolved_ip": resolved_ip,
        "issued_to": issued_to,
        "issuer_c": issuer_c,
        "issuer_o": issuer_o,
        "cert_sn": cert_sn,
        "cert_sha1": cert_sha1,
        "cert_alg": cert_alg,
        "cert_exp": cert_exp,
        "cert_valid": cert_valid,
        "valid_from": valid_from,
        "valid_till": valid_till,
        "validity_days": validity_days,
        "days_left": days_left,
        "version": version,
        "subject_alt_names": subject_alt_names,
        "public_key_algorithm": public_key_algorithm,
        "public_key_size": public_key_size,
        "signature_algorithm_oid": signature_algorithm_oid,
        "issuer_full": issuer_full,
        "subject_full": subject_full,
        "is_self_signed": is_self_signed,
        "extensions": extensions,
        "cipher": cipher,
        "session_reused": session_reused,
    }

@app.post("/check-ssl")
async def check_ssl(request: SSLRequest):
    results = []
    for url in request.urls:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            cert, der_cert, version, resolved_ip, cipher, session_reused = get_ssl_info(host)
            result = parse_cert(cert, der_cert, version, resolved_ip, cipher, session_reused)
            results.append({
                "host": host,
                "status": "ok",
                "result": result
            })
        except Exception as e:
            results.append({
                "host": host,
                "status": "error",
                "error": str(e)
            })
    return {
        "version": "1.0",
        "response_time_sec": None,  # You can add timing if you want
        "status": "ok",
        "results": results
    } 