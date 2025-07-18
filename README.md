# SSL Checker API

A FastAPI-based web API to check SSL certificate details for one or more domains, built from scratch in Python.

## Features
- Check SSL certificate details for any domain
- Returns issuer, validity, SHA1, serial, algorithm, and more
- Returns subject alternative names, public key info, signature OID, full issuer/subject, self-signed status, all extensions, cipher, session reuse, and more
- Supports multiple domains in a single request
- Simple REST API
- Dockerized for easy deployment
- Health check endpoint

## Requirements
- Python 3.11+
- Or Docker

## Installation (Python)

1. Clone the repository and navigate to the project directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the API:
   ```bash
   uvicorn main:app --reload
   ```

## Installation (Docker)

1. Build the Docker image:
   ```bash
   docker build -t ssl-checker-api .
   ```
2. Run the container:
   ```bash
   docker run -p 8000:8000 ssl-checker-api
   ```

## API Usage

### Endpoint
- `POST /check-ssl`

### Request Body
Send a JSON object with a list of URLs:
```json
{
  "urls": ["https://example.com", "https://google.com"]
}
```

### Example with curl
```bash
curl -X POST "http://localhost:8000/check-ssl" \
     -H "Content-Type: application/json" \
     -d '{"urls": ["https://example.com", "https://google.com"]}'
```

### Response
Returns certificate details for each domain, e.g.:
```json
{
  "version": "1.0",
  "response_time_sec": null,
  "status": "ok",
  "results": [
    {
      "host": "example.com",
      "status": "ok",
      "result": {
        "host": "example.com",
        "resolved_ip": "93.184.216.34",
        "issued_to": "example.com",
        "issuer_c": "US",
        "issuer_o": "Let's Encrypt",
        "cert_sn": "0x123456...",
        "cert_sha1": "abcdef...",
        "cert_alg": "sha256",
        "cert_exp": false,
        "cert_valid": true,
        "valid_from": "May  1 00:00:00 2024 GMT",
        "valid_till": "Jul 30 23:59:59 2024 GMT",
        "validity_days": 90,
        "days_left": 60,
        "version": "TLSv1.3",
        "subject_alt_names": ["example.com", "www.example.com"],
        "public_key_algorithm": "RSAPublicKey",
        "public_key_size": 2048,
        "signature_algorithm_oid": "1.2.840.113549.1.1.11",
        "issuer_full": "CN=R3,O=Let's Encrypt,C=US",
        "subject_full": "CN=example.com",
        "is_self_signed": false,
        "extensions": {
          "subjectAltName": "<...>",
          "basicConstraints": "<...>",
          "keyUsage": "<...>"
        },
        "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256],
        "session_reused": false
      }
    },
    ...
  ]
}
```

### Health Check Endpoint
- `GET /health`
Returns:
```json
{"status": "ok"}
```

## License
MIT 