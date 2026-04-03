import json
import base64

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec

from .models import Credential


@csrf_exempt
def service_info(request):
    """
    Returns static information about the QTSP service (CSC API v2 /info).
    """
    
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
    """
    Returns a list of valid credential IDs (CSC API v2 credentials/list).
    """
    
    if request.method != "POST":
        return JsonResponse({"error": "Use POST"}, status=400)

    credentials = Credential.objects.filter(is_valid=True)
    credential_ids = [c.credential_id for c in credentials]

    return JsonResponse({
        "credentialIDs": credential_ids
    })


@csrf_exempt
def credentials_info(request):
    """
    Returns key and status info for a specific credential (CSC API v2 credentials/info).
    """

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
    """
    Signs one or more base64-encoded hashes using the credential's ECDSA private key 
    (CSC API v2 signatures/signHash).
    """
    
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