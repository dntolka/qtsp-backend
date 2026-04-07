import json
import base64
import uuid
import time
import os

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec

from .models import Credential

CLIENT_ID = os.environ.get("QTSP_CLIENT_ID", "http://localhost:8000")
RESPONSE_URI = os.environ.get("QTSP_RESPONSE_URI", "http://localhost:8000/oid4vp/response")


@csrf_exempt
def service_info(request):
    """Returns static information about the QTSP service (CSC API v2 /info)."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    return JsonResponse({
        "specs": "2.0.0.0",
        "name": "GRNET QTSP",
        "logo": "",
        "region": "GR",
        "lang": "en-US",
        "description": "GRNET Qualified Trust Service Provider",
        "authType": ["external"],
        "oauth2": "http://localhost:8000",
        "methods": [
            "info",
            "credentials/list",
            "credentials/info",
            "signatures/signHash"
        ]
    })


@csrf_exempt
def credentials_list(request):
    """Returns a list of valid credential IDs (CSC API v2 credentials/list)."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    credentials = Credential.objects.filter(is_valid=True)
    credential_ids = [c.credential_id for c in credentials]

    return JsonResponse({
        "credentialIDs": credential_ids
    })


@csrf_exempt
def credentials_info(request):
    """Returns key and status info for a specific credential (CSC API v2 credentials/info)."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    try:
        body = json.loads(request.body) if request.body else {}
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    credential_id = body.get("credentialID")

    if not credential_id:
        return JsonResponse({"error": "Missing credentialID"}, status=400)

    try:
        credential = Credential.objects.get(credential_id=credential_id)
    except Credential.DoesNotExist:
        return JsonResponse({"error": "Unknown credentialID"}, status=404)

    return JsonResponse({
        "credentialID": credential.credential_id,
        "status": "valid" if credential.is_valid else "invalid",
        "key": {
            "status": "enabled" if credential.is_valid else "disabled",
            "algo": [credential.key_algorithm],
            "len": 256,
            "curve": credential.curve
        }
    })


@csrf_exempt
def sign_hash(request):
    """Signs one or more base64-encoded hashes using the credential's ECDSA private key (CSC API v2 signatures/signHash)."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    credential_id = body.get("credentialID")
    hash_values = body.get("hashes", [])
    hash_algorithm_oid = body.get("hashAlgorithmOID")
    sign_algo = body.get("signAlgo")

    if not credential_id:
        return JsonResponse({"error": "Missing credentialID"}, status=400)

    if not hash_values:
        return JsonResponse({"error": "Missing hashes"}, status=400)

    if not hash_algorithm_oid:
        return JsonResponse({"error": "Missing hashAlgorithmOID"}, status=400)

    if not sign_algo:
        return JsonResponse({"error": "Missing signAlgo"}, status=400)

    try:
        credential = Credential.objects.get(credential_id=credential_id)
    except Credential.DoesNotExist:
        return JsonResponse({"error": "Unknown credentialID"}, status=404)

    if not credential.is_valid:
        return JsonResponse({"error": "Credential is not valid"}, status=400)

    if credential.key_algorithm != sign_algo:
        return JsonResponse({"error": "signAlgo does not match credential algorithm"}, status=400)

    private_key = load_pem_private_key(credential.private_key_pem.encode("utf-8"), password=None)
    signatures = []

    for item in hash_values:
        data = base64.b64decode(item)
        signature = private_key.sign(data, ec.ECDSA(crypto_hashes.SHA256()))
        signature_b64 = base64.b64encode(signature).decode("utf-8")
        signatures.append(signature_b64)

    return JsonResponse({
        "credentialID": credential_id,
        "signatures": signatures
    })


@csrf_exempt
def oid4vp_authorize(request):
    """Builds an OID4VP authorization request and returns it for the wallet (QR or deep link)."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    now = int(time.time())

    authorization_request = {
        "client_id": CLIENT_ID,
        "client_id_scheme": "http",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": RESPONSE_URI,
        "nonce": nonce,
        "state": state,
        "iss": CLIENT_ID,
        "aud": "https://self-issued.me/v2",
        "iat": now,
        "exp": now + 300,
        "dcql_query": {
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                    ]
                }
            ]
        }
    }

    cache.set(f"oid4vp_session_{state}", {"nonce": nonce}, timeout=300)

    return JsonResponse({
        "state": state,
        "request": authorization_request,
    })


@csrf_exempt
def oid4vp_response(request):
    """Receives the VP Token from the wallet, validates it, and extracts PID attributes."""
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    vp_token = body.get("vp_token")
    state = body.get("state")

    if not vp_token:
        return JsonResponse({"error": "Missing vp_token"}, status=400)

    if not state:
        return JsonResponse({"error": "Missing state"}, status=400)

    session = cache.get(f"oid4vp_session_{state}")
    if not session:
        return JsonResponse({"error": "Unknown or expired state"}, status=400)

    try:
        # SD-JWT format: <header>.<payload>.<signature>~<disclosure1>~...~<kb-jwt>
        parts = vp_token.split("~")
        sd_jwt_part = parts[0]
        payload_b64 = sd_jwt_part.split(".")[1]
        # Add padding if needed
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        attributes = {
            "given_name": payload.get("given_name"),
            "family_name": payload.get("family_name"),
        }
    except Exception as e:
        return JsonResponse({"error": f"VP Token validation failed: {str(e)}"}, status=400)

    cache.delete(f"oid4vp_session_{state}")

    return JsonResponse({
        "status": "ok",
        "attributes": attributes,
    })
