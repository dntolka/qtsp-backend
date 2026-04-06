# QTSP Backend

REST API implementation for the **QTSP (Qualified Trust Service Provider)** role as part of the **WE BUILD WP4** programme (GRNET).

The API is based on the **CSC API v2.0** (Cloud Signature Consortium) specification and is designed for interoperability with EU digital identity wallets within the EUDI Wallet ecosystem.

## Tech Stack

- Python / Django 6
- PostgreSQL
- `cryptography` (ECDSA/P-256 signatures)

## Setup

```bash
git clone <repo-url>
cd qtsp_backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create the database in PostgreSQL:

```sql
CREATE USER qtsp WITH PASSWORD 'yourpassword';
CREATE DATABASE qtsp OWNER qtsp;
```

Create a `.env` file in the project root:

```
DB_NAME=qtsp
DB_USER=qtsp
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_PORT=5432
```

Run migrations and start the server:

```bash
python manage.py migrate
python manage.py runserver
```

## API Endpoints

### `POST /csc/v2/info`

Returns information about the QTSP service.

**Response:**
```json
{
  "specs": "2.0.0.0",
  "name": "GRNET QTSP",
  "region": "GR",
  "lang": "en-US",
  "authType": ["external"],
  "methods": ["info", "credentials/list", "credentials/info", "signatures/signHash"]
}
```

---

### `POST /csc/v2/credentials/list`

Returns a list of valid credential IDs.

**Response:**
```json
{
  "credentialIDs": ["cred-001", "cred-002"]
}
```

---

### `POST /csc/v2/credentials/info`

Returns information about a specific credential.

**Request:**
```json
{
  "credentialID": "cred-001"
}
```

**Response:**
```json
{
  "credentialID": "cred-001",
  "status": "valid",
  "key": {
    "status": "enabled",
    "algo": ["ECDSA"],
    "len": 256,
    "curve": "P-256"
  }
}
```

---

### `POST /csc/v2/signatures/signHash`

Signs hashes using ECDSA/SHA-256 with the credential's private key.

**Request:**
```json
{
  "credentialID": "cred-001",
  "hashes": ["<hash1>", "<hash2>"],
  "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
  "signAlgo": "ECDSA"
}
```

**Response:**
```json
{
  "credentialID": "cred-001",
  "signatures": ["<base64-signature-1>", "<base64-signature-2>"]
}
```

## Data Models

### User
| Field | Type | Description |
|-------|------|-------------|
| `user_hash` | CharField | Unique user identifier |
| `given_name` | CharField | First name |
| `surname` | CharField | Last name |
| `issuing_country` | CharField | Country of issuance |

### Credential
| Field | Type | Description |
|-------|------|-------------|
| `credential_id` | CharField | Unique credential identifier |
| `user` | ForeignKey | Associated user |
| `key_algorithm` | CharField | Key algorithm (default: ECDSA) |
| `curve` | CharField | Curve (default: P-256) |
| `is_valid` | BooleanField | Credential status |
| `private_key_pem` | TextField | Private key in PEM format |

## Missing / Next Steps

- [ ] OID4VP flow — QTSP acting as verifier for PID validation from wallet
- [ ] X.509 certificate issuance for user attributes
- [ ] Callback / polling mechanism for sending signed document to RP
- [ ] QEAA data model (digital seal with detached ECDSA)
- [ ] Revocation list API
- [ ] Authentication / authorization (OAuth2)

## References

- [CSC API v2.0 Specification](https://cloudsignatureconsortium.org/)
- [EUDI Reference Implementation (Java)](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java)

