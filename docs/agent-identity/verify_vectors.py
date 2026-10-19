"""Recompute docs/agent-identity/test-vectors.json independently of any Agent Identity implementation.

Usage: python verify_vectors.py [path/to/test-vectors.json]
Requires the `cryptography` package.
"""
import base64, hashlib, json, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

import os
PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-vectors.json")
V = json.load(open(PATH, encoding="utf-8"))
problems = []
def check(cond, msg):
    if not cond:
        problems.append(msg)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def raw_to_der(raw): return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
def der_to_raw(der):
    r, s = decode_dss_signature(der); return r.to_bytes(32, "big") + s.to_bytes(32, "big")

# Keys.
priv = {}
for k in V["keys"]:
    key = serialization.load_der_private_key(base64.b64decode(k["private_key_pkcs8"]), None)
    priv[k["name"]] = key
    sec1 = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    check(base64.b64encode(sec1).decode() == k["public_key_sec1"], f"key {k['name']}: public_key_sec1 mismatch")

# Root.
root = x509.load_der_x509_certificate(base64.b64decode(V["root"]["certificate"]))
check(isinstance(root.public_key(), ec.EllipticCurvePublicKey) and root.public_key().curve.name == "secp256r1", "root: not P-256")
root.public_key().verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
years = (root.not_valid_after_utc - root.not_valid_before_utc).days / 365.25
check(9.9 < years < 10.1, f"root: validity {years:.2f} y")
print("root CN:", root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, f"validity {years:.2f} y")

# Registered certificates.
reg = {}
for r in V["http_signature"]["registered"]:
    der = base64.b64decode(r["certificate"])
    c = x509.load_der_x509_certificate(der)
    check(b64u(hashlib.sha256(der).digest()) == r["keyid"], f"registered {r.get('name')}: keyid != base64url(SHA-256(cert DER))")
    pub = c.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    check(base64.b64encode(pub).decode() == r["public_key_sec1"], f"registered {r.get('name')}: public key mismatch")
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    check(cn == r["identity_id"], f"registered {r.get('name')}: CN {cn} != identity_id")
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    check(f"urn:uuid:{r['identity_id']}" in list(san.get_values_for_type(x509.UniformResourceIdentifier)), f"registered {r.get('name')}: SAN URI")
    eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    check(ExtendedKeyUsageOID.CLIENT_AUTH in list(eku), f"registered {r.get('name')}: EKU clientAuth")
    ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
    check(ku.digital_signature, f"registered {r.get('name')}: KU digitalSignature")
    if c.issuer == root.subject:
        root.public_key().verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    reg[r["keyid"]] = (r, c)
print("registered certs:", len(reg))

key_by_sec1 = {}
for name, key in priv.items():
    sec1 = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_by_sec1[base64.b64encode(sec1).decode()] = key

def parse_sig_input(h):
    label, rest = h.split("=", 1)
    close = rest.index(")")
    comps = [c.strip('"') for c in rest[1:close].split(" ") if c]
    return label, rest, comps

def my_base(case):
    h = case["headers"]
    label, params, comps = parse_sig_input(h["signature-input"])
    lines = []
    for comp in comps:
        if comp == "@method": lines.append(f'"@method": {case["method"]}')
        elif comp == "content-digest": lines.append(f'"content-digest": {h.get("content-digest", "")}')
        else: lines.append(f'"{comp}": ?')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)

def verify_raw(pub, msg, raw):
    try:
        if len(raw) != 64: return False
        pub.verify(raw_to_der(raw), msg, ec.ECDSA(hashes.SHA256())); return True
    except Exception:
        return False

det_ok = det_total = 0
def check_deterministic(name, key, msg, raw):
    global det_ok, det_total
    try:
        der = key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    except Exception as e:
        print("deterministic signing unavailable:", e); return
    det_total += 1
    if der_to_raw(der) == raw: det_ok += 1
    else: problems.append(f"{name}: signature is not the RFC 6979 deterministic signature")

sig_ok_cases = 0
for case in V["http_signature"]["cases"]:
    name = case["name"]; h = case["headers"]
    if "signature_base" in case and case["expected"] == "ok":
        # Negative cases carry the originally signed base (CONTRACT.md §6 note), so only positive cases are compared.
        mine = my_base(case) if "signature-input" in h and h["signature-input"].startswith("sig=") and h["signature-input"].count("sig") >= 1 else None
        if mine is not None and "," not in h["signature-input"].split(")")[0] and h["signature-input"].count("=(") == 1:
            check(mine == case["signature_base"], f"{name}: my signature base differs from vector")
    if case["expected"] == "ok":
        sig_hdr = h["signature"]
        raw = base64.b64decode(sig_hdr.split(":")[1])
        _, params, comps = parse_sig_input(h["signature-input"])
        keyid = params.split('keyid="')[1].split('"')[0]
        r, cert = reg[keyid]
        msg = case["signature_base"].encode()
        check(my_base(case) == case["signature_base"], f"{name}: base mismatch")
        check(verify_raw(cert.public_key(), msg, raw), f"{name}: expected ok but signature does not verify")
        if case["endpoint"] == "renew":
            dig = base64.b64encode(hashlib.sha256(case["body"].encode()).digest()).decode()
            check(h["content-digest"] == f"sha-256=:{dig}:", f"{name}: content-digest != SHA-256(body)")
        check_deterministic(name, key_by_sec1[r["public_key_sec1"]], msg, raw)
        sig_ok_cases += 1
    elif name in ("wrong_key", "body_tampered", "signature_truncated", "signature_der_encoded"):
        _, params, _ = parse_sig_input(h["signature-input"])
        keyid = params.split('keyid="')[1].split('"')[0]
        if keyid in reg:
            raw = base64.b64decode(h["signature"].split(":")[1]) if ":" in h["signature"] else b""
            msg = my_base(case).encode()
            ok = verify_raw(reg[keyid][1].public_key(), msg, raw)
            if name == "body_tampered":
                dig = base64.b64encode(hashlib.sha256(case["body"].encode()).digest()).decode()
                check(h["content-digest"] != f"sha-256=:{dig}:", f"{name}: digest unexpectedly matches the tampered body")
            else:
                check(not ok, f"{name}: negative case signature verifies")
print("http ok cases verified:", sig_ok_cases)

# Channel proof.
cp = V["channel_proof"]
domain = b"devolutions-agent-identity/v1/channel-proof"
challenge = base64.b64decode(cp["challenge"])
check(len(challenge) == 32, "channel proof: challenge not 32 bytes")
msg = domain + b"\x00" + challenge + cp["connect_nonce"].encode()
check(msg.hex() == cp["message_hex"], "channel proof: message_hex != domain||0x00||challenge||nonce")
connect_case = next(c for c in V["http_signature"]["cases"] if c["name"] == cp["connect_case"])
check(f'nonce="{cp["connect_nonce"]}"' in connect_case["headers"]["signature-input"], "channel proof: nonce not the connect case nonce")
pub = serialization.load_der_public_key(b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" + base64.b64decode(cp["public_key_sec1"]))
for c in cp["cases"]:
    raw = base64.b64decode(c["proof"])
    got = verify_raw(pub, msg, raw)
    check(got == c["expected_valid"], f"channel proof {c['name']}: verify={got}, expected {c['expected_valid']}")
    if c["name"] == "valid":
        check_deterministic("channel proof valid", key_by_sec1[cp["public_key_sec1"]], msg, raw)

# RFC 9421 B.2.4.
b = V["rfc9421_b_2_4"]
bpub = serialization.load_der_public_key(base64.b64decode(b["public_key_spki"]))
braw = base64.b64decode(b.get("signature") or b["signature_header"].split(":")[1])
check(verify_raw(bpub, b["signature_base"].encode(), braw), "RFC 9421 B.2.4 does not verify")
print("rfc9421 B.2.4 base first line:", b["signature_base"].splitlines()[0])

print(f"deterministic RFC 6979 reproduced: {det_ok}/{det_total}")
print("PROBLEMS:" if problems else "ALL CHECKS PASSED")
for p in problems: print(" -", p)
