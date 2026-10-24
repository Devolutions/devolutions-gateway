"""Recompute docs/agent-identity/test-vectors.json independently of any Agent Identity implementation.

Usage: python verify_vectors.py [--table] [--self-test] [path/to/test-vectors.json]

Every http_signature case and sequence runs through a CONTRACT.agent-identity.md §6 evaluator written from the
contract text alone. It has its own parser for the RFC 8941 subset the profile uses, because a
structured-field library keeps only the last of repeated keys and accepts non-canonical base64,
which are exactly what §6 step 1 must reject. Each negative case is also checked for isolation:
with its failing step bypassed, the request must not fail later for another reason.
--table prints one row per case. --self-test builds, from the file's positive cases and test keys,
the step-1 violations that no vector covers yet.
Requires the `cryptography` package.
"""
import argparse, base64, hashlib, json, os, re, sys
from collections import namedtuple
from decimal import Decimal, ROUND_HALF_EVEN
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

problems, notes = [], []
det = {"ok": 0, "total": 0}


def check(cond, msg):
    if not cond:
        problems.append(msg)
    return bool(cond)


# ---------------------------------------------------------------------------- crypto helpers

def b64(b): return base64.b64encode(b).decode()
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def sec1(pub): return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
def cn(cert): return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
def raw_to_der(raw): return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def der_to_raw(der):
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(pub, msg, raw):
    """ECDSA P-256 / SHA-256, raw 64-byte r||s (CONTRACT.agent-identity.md §6, §7.3)."""
    if len(raw) != 64:
        return False
    try:
        pub.verify(raw_to_der(raw), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_raw(key, msg):
    return der_to_raw(key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))


def signed_by(issuer_pub, cert):
    try:
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def check_deterministic(name, key, msg, raw):
    try:
        mine = sign_raw(key, msg)
    except Exception as e:
        print("deterministic signing unavailable:", e)
        return
    det["total"] += 1
    if check(mine == raw, f"{name}: signature is not the RFC 6979 deterministic signature"):
        det["ok"] += 1


# ---------------------------------------------------------------------------- base64

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_canonical(text):
    """Standard base64 with padding, in its canonical form (CONTRACT.agent-identity.md §6; RFC 4648 §3.2, §3.5, §4)."""
    data = text.rstrip("=")
    pad = len(text) - len(data)
    if any(c not in B64_ALPHABET for c in data):
        raise ValueError("character outside the base64 alphabet")
    if pad == 0 and len(data) % 4:
        raise ValueError("padding missing")
    if len(text) % 4 or pad > 2:
        raise ValueError("wrong padding")
    if pad and B64_ALPHABET.index(data[-1]) & (0b1111 if pad == 2 else 0b11):
        raise ValueError("non-zero pad bits")
    out = base64.b64decode(text, validate=True)
    if b64(out) != text:
        raise ValueError("not canonical")
    return out


def b64_lenient(text):
    """What RFC 8941 §4.2.7 lets a parser accept: padding missing, non-zero pad bits."""
    data = text.rstrip("=")
    if any(c not in B64_ALPHABET for c in data) or len(data) % 4 == 1:
        raise ValueError("not base64")
    return base64.b64decode(data + "=" * (-len(data) % 4))


# ---------------------------------------------------------------------------- RFC 8941 subset

class SFError(ValueError):
    pass


class Token(str):
    """sf-token, kept apart from sf-string."""


class Bytes:
    """sf-binary; the raw text is kept so that its canonical form can be checked."""
    def __init__(self, text): self.text = text
    def __repr__(self): return f":{self.text}:"


class InnerList(list):
    pass


LCALPHA = set("abcdefghijklmnopqrstuvwxyz")
DIGIT = set("0123456789")
ALPHA = LCALPHA | set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
KEY_CHARS = LCALPHA | DIGIT | set("_-.*")
TOKEN_CHARS = ALPHA | DIGIT | set("!#$%&'*+-.^_`|~:/")


class _Input:
    def __init__(self, text):
        if any(not (0x20 <= ord(c) <= 0x7E or c == "\t") for c in text):
            raise SFError("non-printable or non-ASCII character")
        self.s, self.i = text, 0

    def peek(self): return self.s[self.i] if self.i < len(self.s) else ""

    def take(self):
        c = self.peek()
        self.i += 1
        return c

    def skip(self, chars):
        while self.peek() and self.peek() in chars:
            self.i += 1


def parse_dictionary(text):
    """RFC 8941 §4.2.2, except that every member is returned in order, repeated keys included."""
    p = _Input(text)
    p.skip(" ")
    members = []
    while p.peek():
        key = _key(p)
        if p.peek() == "=":
            p.take()
            members.append((key, _inner_list(p) if p.peek() == "(" else _item(p)))
        else:
            members.append((key, (True, _params(p))))
        p.skip(" \t")
        if not p.peek():
            break
        if p.take() != ",":
            raise SFError(f"expected ',' at offset {p.i - 1}")
        p.skip(" \t")
        if not p.peek():
            raise SFError("trailing comma")
    return members


def _key(p):
    if not (p.peek() in LCALPHA or p.peek() == "*"):
        raise SFError(f"bad key at offset {p.i}")
    start = p.i
    while p.peek() and p.peek() in KEY_CHARS:
        p.i += 1
    return p.s[start:p.i]


def _params(p):
    params = []  # a list, so that a repeated parameter stays visible
    while p.peek() == ";":
        p.take()
        p.skip(" ")
        key, value = _key(p), True
        if p.peek() == "=":
            p.take()
            value = _bare(p)
        params.append((key, value))
    return params


def _item(p):
    return _bare(p), _params(p)


def _inner_list(p):
    p.take()
    items = InnerList()
    while p.peek():
        p.skip(" ")
        if p.peek() == ")":
            p.take()
            return items, _params(p)
        items.append(_item(p))
        if p.peek() not in (" ", ")"):
            raise SFError(f"bad inner list at offset {p.i}")
    raise SFError("unterminated inner list")


def _bare(p):
    c = p.peek()
    if c == "-" or c in DIGIT:
        return _number(p)
    if c == '"':
        return _string(p)
    if c == "*" or c in ALPHA:
        start = p.i
        p.take()
        while p.peek() and p.peek() in TOKEN_CHARS:
            p.i += 1
        return Token(p.s[start:p.i])
    if c == ":":
        p.take()
        end = p.s.find(":", p.i)
        if end < 0:
            raise SFError("unterminated byte sequence")
        text, p.i = p.s[p.i:end], end + 1
        if any(ch not in B64_ALPHABET + "=" for ch in text):
            raise SFError("byte sequence outside the base64 alphabet")
        return Bytes(text)
    if c == "?":
        p.take()
        b = p.take()
        if b not in ("0", "1"):
            raise SFError("bad boolean")
        return b == "1"
    raise SFError(f"bad item at offset {p.i}")


def _number(p):
    neg = p.peek() == "-"
    if neg:
        p.take()
    if not (p.peek() and p.peek() in DIGIT):
        raise SFError("bad number")
    num, decimal = "", False
    while p.peek() and (p.peek() in DIGIT or (p.peek() == "." and not decimal)):
        if p.peek() == ".":
            if len(num) > 12:
                raise SFError("decimal too long")
            decimal = True
        num += p.take()
        if len(num) > (16 if decimal else 15):
            raise SFError("number too long")
    if not decimal:
        return -int(num) if neg else int(num)
    if num.endswith(".") or len(num.split(".")[1]) > 3:
        raise SFError("bad decimal")
    return Decimal(("-" if neg else "") + num)


def _string(p):
    p.take()
    out = []
    while p.peek():
        c = p.take()
        if c == "\\":
            c = p.take()
            if c not in ('"', "\\"):
                raise SFError("bad escape")
        elif c == '"':
            return "".join(out)
        elif c == "\t":
            raise SFError("bad string character")
        out.append(c)
    raise SFError("unterminated string")


def ser_bare(v):
    """RFC 8941 §4.1.3 - §4.1.9."""
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, Decimal):
        i, f = format(v.quantize(Decimal("0.001"), ROUND_HALF_EVEN), "f").split(".")
        return f"{i}.{f.rstrip('0') or '0'}"
    if isinstance(v, Token):
        return str(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    try:
        return f":{b64(b64_lenient(v.text))}:"
    except ValueError:
        return f":{v.text}:"


def ser_params(params):
    return "".join(f";{k}" if v is True else f";{k}={ser_bare(v)}" for k, v in params)


def ser_item(item):
    return ser_bare(item[0]) + ser_params(item[1])


def ser_inner_list(items, params):
    return "(" + " ".join(ser_item(i) for i in items) + ")" + ser_params(params)


def ser_dictionary(members):
    return ", ".join(k if v[0] is True else f"{k}={ser_member(v)}" for k, v in members)


def ser_member(v):
    return ser_inner_list(*v) if isinstance(v[0], InnerList) else ser_item(v)


def is_type(v, t):
    if t is int:
        return isinstance(v, int) and not isinstance(v, bool)
    return isinstance(v, str) and not isinstance(v, Token)


def coerce(v, t):
    """The value a verifier that ignores RFC 8941 types would read, or None."""
    if is_type(v, t):
        return v
    if t is int:
        if isinstance(v, Decimal) and v == v.to_integral_value():
            return int(v)
        return int(v) if isinstance(v, str) and re.fullmatch(r"-?\d+", v) else None
    if isinstance(v, Token):
        return str(v)
    try:
        return b64_lenient(v.text).decode("ascii") if isinstance(v, Bytes) else None
    except (ValueError, UnicodeDecodeError):
        return None


URL_ALPHABET = B64_ALPHABET[:62] + "-_"


def is_b64url(text, size):
    """`base64url` (CONTRACT.agent-identity.md Definitions: RFC 4648 §5, no padding) of exactly `size` bytes, in canonical form."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        return False
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return len(raw) == size and b64u(raw) == text


def b64url_lenient(text):
    """The bytes a lenient decoder reads from base64url text: either alphabet, any padding, pad bits ignored."""
    data = text.rstrip("=").replace("+", "-").replace("/", "_")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", data) or len(data) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def normalized_thumbprint(text):
    """The thumbprint a verifier without the keyid format check would look up."""
    raw = b64url_lenient(text)
    return None if raw is None else b64u(raw)


# ---------------------------------------------------------------------------- CONTRACT.agent-identity.md §6 evaluator

SI = "signature_invalid"
OPERATIONS = {  # §6 table: endpoint -> (tag, covered components, accepted statuses, validity rule)
    "renew": ("renew", ("@method", "content-digest"), ("current", "pending"), "grace"),
    "confirm": ("confirm", ("@method",), ("pending", "current"), "unexpired"),
    "check-in": ("check-in", ("@method", "content-digest"), ("current", "pending"), "unexpired"),
    "connect": ("connect", ("@method",), ("current", "pending"), "unexpired"),
}
PARAMS = {"created": int, "expires": int, "nonce": str, "keyid": str, "alg": str, "tag": str}
ALG = "ecdsa-p256-sha256"
RULES = {  # rule -> (step, code)
    "parse": (1, SI), "dup": (1, SI), "label": (1, SI), "member": (1, SI), "member-param": (1, SI), "params": (1, SI),
    "param-type": (1, SI), "keyid-format": (1, SI), "nonce-format": (1, SI), "b64": (1, SI), "alg": (1, SI),
    "components": (1, SI), "component-param": (1, SI), "digest-member": (1, SI), "digest-param": (1, SI),
    "tag": (2, SI), "window": (3, "clock_skew"),
    "keyid": (4, "identity_unknown"), "revoked": (4, "identity_revoked"), "validity": (4, "certificate_expired"),
    "digest": (5, SI), "signature": (5, SI), "nonce": (6, SI),
}
RELAXABLE = set(RULES) - {"parse", "signature", "nonce"}
Outcome = namedtuple("Outcome", "code step rule detail")


class Reject(Exception):
    def __init__(self, rule, detail):
        super().__init__(detail)
        self.rule, self.detail = rule, detail


def evaluate(req, registry, nonces, relax=frozenset(), keys=None, derived=None, trace=None):
    """Run §6 steps 1-6 on `req` and return `ok` or the outcome of the earliest failing step.

    `relax` names rules to bypass, as a verifier missing them would; for a relaxed `keyid`, `keys`
    (thumbprint -> public key) supplies the claimed key, and `derived` supplies derived component
    values that the request does not carry. `trace["base"]` receives the signature base."""
    try:
        _evaluate(req, registry, nonces, relax, keys or {}, derived or {}, {} if trace is None else trace)
        return Outcome("ok", None, None, "")
    except Reject as r:
        step, code = RULES[r.rule]
        return Outcome(code, step, r.rule, r.detail)


def _evaluate(req, registry, nonces, relax, keys, derived, trace):
    tag, components, statuses, validity = OPERATIONS[req["endpoint"]]
    headers = {k.lower(): v for k, v in req["headers"].items()}
    now = req["now"]

    def need(ok, rule, detail):
        if not ok and rule not in relax:
            raise Reject(rule, detail)
        return ok

    def dictionary(name):
        if name not in headers:
            raise Reject("parse", f"{name} missing")
        try:
            members = parse_dictionary(headers[name])
        except SFError as e:
            raise Reject("parse", f"{name}: {e}")
        keys_ = [k for k, _ in members]
        need(len(set(keys_)) == len(keys_), "dup", f"{name}: repeated member in {keys_}")
        return dict(members)  # as an RFC 8941 parser: the last value, at the first position

    # Step 1 (§6): one `sig` member in each field; exact parameters and types; no member or component
    # parameters; keyid and nonce formats; canonical base64; alg; exact components; one sha-256 digest.
    inputs, signatures = dictionary("signature-input"), dictionary("signature")
    need(list(inputs) == ["sig"] and list(signatures) == ["sig"], "label",
         f"labels {list(inputs)} / {list(signatures)}, want exactly one signature labelled sig")
    label = "sig" if "sig" in inputs else next(iter(inputs), None)
    if label not in signatures:
        raise Reject("label", f"no Signature member for label {label!r}")
    (inner, sig_params), (sig_value, value_params) = inputs[label], signatures[label]
    if not need(isinstance(inner, InnerList) and isinstance(sig_value, Bytes), "member",
                "Signature-Input member is not an inner list, or Signature member is not a byte sequence"):
        raise Reject("member", "member types unusable")
    need(not value_params, "member-param", f"parameter on the Signature member: {ser_params(value_params)}")
    names = [k for k, _ in sig_params]
    need(len(set(names)) == len(names), "dup", f"repeated signature parameter in {names}")
    params = dict(sig_params)
    need(set(params) == set(PARAMS), "params", f"parameters {list(params)}")
    need(all(is_type(params[k], t) for k, t in PARAMS.items() if k in params), "param-type",
         "wrong type: " + ser_params([(k, params[k]) for k, t in PARAMS.items() if k in params and not is_type(params[k], t)]))
    p = {k: v for k, t in PARAMS.items() if k in params for v in [coerce(params[k], t)] if v is not None}
    keyid, nonce = p.get("keyid"), p.get("nonce")
    need(keyid is None or is_b64url(keyid, 32), "keyid-format", f"keyid {keyid!r} is not a thumbprint")
    need(nonce is None or is_b64url(nonce, 16), "nonce-format", f"nonce {nonce!r} is not base64url of 16 bytes")
    need(p.get("alg") == ALG, "alg", f"alg {params.get('alg')!r}")
    need(all(is_type(n, str) for n, _ in inner) and tuple(n for n, _ in inner) == components,
         "components", f"covered {ser_inner_list(inner, [])}, want {components} for {req['endpoint']}")
    need(not any(ps for _, ps in inner), "component-param", f"parameter on a covered component: {ser_inner_list(inner, [])}")
    digest_text = None
    if "content-digest" in components:  # §6: a header the operation does not cover is ignored
        if need("content-digest" in headers, "digest-member", "Content-Digest missing"):
            digests = dictionary("content-digest")
            member = digests.get("sha-256")
            usable = member is not None and isinstance(member[0], Bytes)
            need(list(digests) == ["sha-256"] and usable, "digest-member",
                 f"Content-Digest members {list(digests)}, want exactly one sha-256 byte sequence")
            need(not (member and member[1]), "digest-param", "parameter on the Content-Digest member")
            digest_text = member[0].text if usable else None

    def decode(text, what):
        try:
            return b64_canonical(text)
        except ValueError as e:
            need(False, "b64", f"{what}: {e}")
        try:
            return b64_lenient(text)
        except ValueError as e:
            raise Reject("b64", f"{what}: {e}")

    signature = decode(sig_value.text, "Signature")
    digest = decode(digest_text, "Content-Digest") if digest_text is not None else None

    # Step 2: tag.
    need(p.get("tag") == tag, "tag", f"tag {params.get('tag')!r} sent to {req['endpoint']}")

    # Step 3: window.
    created, expires = p.get("created"), p.get("expires")
    need(created is not None and expires is not None and 0 < expires - created <= 300
         and created <= now + 60 and expires >= now - 60, "window", f"created={created} expires={expires} now={now}")

    # Step 4: registered certificate, status, revocation, the operation's validity rule.
    cert = registry.get(keyid)
    if cert is None and keyid is not None and "keyid-format" in relax and normalized_thumbprint(keyid) in registry:
        keyid = normalized_thumbprint(keyid)
        cert = registry[keyid]
    if not need(cert is not None and cert["status"] in statuses, "keyid",
                f"keyid {keyid!r} " + ("not registered" if cert is None else f"has status {cert['status']}")):
        if cert is None:
            if keyid not in keys:
                raise Reject("keyid", f"keyid {keyid!r}: no test key to continue with")
            cert = {"public_key": keys[keyid], "revoked": False, "not_before": None, "not_after": None}
    need(not cert["revoked"], "revoked", "identity revoked")
    if cert["not_after"] is not None:
        nb, na = cert["not_before"], cert["not_after"]
        # §6: unexpired while now <= notAfter; renew grace while now < notAfter + (notAfter - notBefore).
        valid = now < na + (na - nb) if validity == "grace" else now <= na
        need(valid, "validity", f"now={now} notBefore={nb} notAfter={na} ({validity})")

    # Step 5: content-digest for renew and check-in, then the signature.
    if "content-digest" in components:
        body = (req.get("body") or "").encode()
        need(digest == hashlib.sha256(body).digest(), "digest", "Content-Digest != SHA-256(body)")
    trace["base"] = base = signature_base(req, headers, inner, list(params.items()), derived)
    need(verify_raw(cert["public_key"], base.encode(), signature), "signature",
         f"{len(signature)}-byte signature does not verify over the recomputed base")

    # Step 6: each (keyid, nonce) at most once, committed only now.
    need(nonce is None or (keyid, nonce) not in nonces, "nonce", "(keyid, nonce) already accepted")
    if nonce is not None:
        nonces.add((keyid, nonce))


def signature_base(req, headers, inner, params, derived):
    """RFC 9421 §2.5, with @signature-params serialized from the received member (§2.3).

    Component parameters only reach here when a relaxed run bypasses `component-param`;
    `sf` and `key` on a dictionary field then follow RFC 9421 §2.1.1 and §2.1.2."""
    lines = []
    for name, ps in inner:
        opts = dict(ps)
        if not is_type(name, str):
            raise Reject("components", f"unsupported component {ser_item((name, ps))}")
        if name == "@method" and not ps:
            value = req["method"]
        elif name in derived and not ps:
            value = derived[name]
        elif not name.startswith("@") and name in headers and set(opts) <= {"sf", "key"}:
            value = headers[name].strip(" \t")
            if ps:
                try:
                    members = dict(parse_dictionary(value))
                    value = ser_member(members[opts["key"]]) if "key" in opts else ser_dictionary(members.items())
                except (SFError, KeyError, TypeError) as e:
                    raise Reject("components", f"component {ser_item((name, ps))}: {e}")
        elif ps:
            raise Reject("components", f"unsupported component {ser_item((name, ps))}")
        else:
            raise Reject("signature", f"component {name!r} cannot be derived from the request")
        lines.append(f"{ser_item((name, ps))}: {value}")
    lines.append(f'"@signature-params": {ser_inner_list(inner, params)}')
    return "\n".join(lines)


# ---------------------------------------------------------------------------- vector material

def check_material(V):
    """Keys, root and registered certificates; returns the evaluator's registry and the test keys."""
    keys = {}
    for k in V["keys"]:
        key = serialization.load_der_private_key(base64.b64decode(k["private_key_pkcs8"]), None)
        name = k["name"]
        check(b64(sec1(key.public_key())) == k["public_key_sec1"], f"key {name}: public_key_sec1 mismatch")
        der = base64.b64decode(k["certificate"])
        cert = x509.load_der_x509_certificate(der)
        check(b64u(hashlib.sha256(der).digest()) == k["thumbprint"], f"key {name}: thumbprint != base64url(SHA-256(cert DER))")
        check(sec1(cert.public_key()) == sec1(key.public_key()), f"key {name}: certificate holds another public key")
        check(cn(cert) == k["identity_id"], f"key {name}: CN != identity_id")
        keys[name] = {"name": name, "private": key, "public": key.public_key(), "thumbprint": k["thumbprint"],
                      "certificate": k["certificate"]}

    root_der = base64.b64decode(V["root"]["certificate"])
    root = x509.load_der_x509_certificate(root_der)
    rpub = root.public_key()
    check(isinstance(rpub, ec.EllipticCurvePublicKey) and rpub.curve.name == "secp256r1", "root: not P-256")
    check(signed_by(rpub, root), "root: self-signature does not verify")
    check(b64u(hashlib.sha256(root_der).digest()) == V["root"]["thumbprint"], "root: thumbprint mismatch")
    check(b64(sec1(rpub)) == V["root"]["public_key_sec1"], "root: public_key_sec1 mismatch")
    years = (root.not_valid_after_utc - root.not_valid_before_utc).days / 365.25
    check(9.9 < years < 10.1, f"root: validity {years:.2f} y")
    print("root CN:", cn(root), f"validity {years:.2f} y")

    registry = {}
    for r in V["http_signature"]["registered"]:
        name = r.get("name")
        der = base64.b64decode(r["certificate"])
        c = x509.load_der_x509_certificate(der)
        check(b64u(hashlib.sha256(der).digest()) == r["keyid"], f"registered {name}: keyid != base64url(SHA-256(cert DER))")
        check(b64(sec1(c.public_key())) == r["public_key_sec1"], f"registered {name}: public key mismatch")
        check(cn(c) == r["identity_id"], f"registered {name}: CN {cn(c)} != identity_id")
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        check(f"urn:uuid:{r['identity_id']}" in san.get_values_for_type(x509.UniformResourceIdentifier), f"registered {name}: SAN URI")
        eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        check(ExtendedKeyUsageOID.CLIENT_AUTH in list(eku), f"registered {name}: EKU clientAuth")
        check(c.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature, f"registered {name}: KU digitalSignature")
        if c.issuer == root.subject:
            check(signed_by(rpub, c), f"registered {name}: not signed by the root")
        check((int(c.not_valid_before_utc.timestamp()), int(c.not_valid_after_utc.timestamp())) == (r["not_before"], r["not_after"]),
              f"registered {name}: not_before/not_after differ from the certificate")
        check(r["certificate_status"] in ("current", "pending", "retired"), f"registered {name}: status {r['certificate_status']}")
        if name in keys:
            check(keys[name]["certificate"] == r["certificate"], f"registered {name}: certificate differs from keys[{name}]")
        registry[r["keyid"]] = {"name": name, "public_key": c.public_key(), "status": r["certificate_status"],
                                "revoked": r["identity_revoked"], "not_before": r["not_before"], "not_after": r["not_after"]}
    print("registered certs:", len(registry))
    return registry, keys


# ---------------------------------------------------------------------------- http_signature cases

ORDER_WORDS = {"tag": (2, SI), "window": (3, "clock_skew"), "keyid": (4, "identity_unknown")}
CODE_STEPS = {"clock_skew": {3}, "identity_unknown": {4}, "identity_revoked": {4}, "certificate_expired": {4}}


def fmt(o): return "ok" if o.code == "ok" else f"{o.code} at step {o.step} ({o.rule}: {o.detail})"
def short(o): return "ok" if o.code == "ok" else f"{o.step}:{o.rule}"


def intended_steps(case):
    d = case.get("description", "")
    m = re.search(r"\bstep (\d)(?:/(\d))?", d)
    if m:
        return {int(g) for g in m.groups() if g}
    m = re.search(r"(\w+) is checked first", d)
    if m and m.group(1) in ORDER_WORDS:
        return {ORDER_WORDS[m.group(1)][0]}
    return CODE_STEPS.get(case["expected"])


def lenient_view(case):
    """(keyid, nonce, signature bytes, notes) as a lenient RFC 8941 parser reads the request."""
    try:
        h = {k.lower(): v for k, v in case["headers"].items()}
        inputs, sigs = dict(parse_dictionary(h["signature-input"])), dict(parse_dictionary(h["signature"]))
        label = "sig" if "sig" in inputs else next(iter(inputs))
        params = dict(inputs[label][1])
        text = sigs[label][0].text
    except (KeyError, StopIteration, SFError, TypeError, AttributeError):
        return None, None, b"", ["request unreadable"]
    try:
        raw, how = b64_canonical(text), []
    except ValueError:
        try:
            raw, how = b64_lenient(text), ["lenient base64"]
        except ValueError:
            raw, how = b"", ["signature not base64"]
    return params.get("keyid"), params.get("nonce"), raw, how


def derived_components(case):
    """Derived components a case does not carry (e.g. @path), valued as its signature_base states them."""
    out = {}
    for line in case.get("signature_base", "").split("\n"):
        m = re.match(r'"(@[a-z-]+)": (.*)$', line)
        if m and m.group(1) not in ("@method", "@signature-params"):
            out[m.group(1)] = m.group(2)
    return out


def claimed_key(keyid, by_thumb, lenient=False):
    """The test key a keyid claims; `lenient` decodes it as a verifier without the keyid format check would,
    and looks the key up by the decoded thumbprint bytes."""
    if not lenient or keyid is None:
        return by_thumb.get(keyid)
    thumb = b64url_lenient(keyid)
    return next((k for k in by_thumb.values() if thumb is not None and b64url_lenient(k["thumbprint"]) == thumb), None)


def stated_signature(case, by_thumb, lenient_keyid=False):
    """Verify the case's signature over its stated signature_base: (claimed key verifies, signer, claimed key, notes)."""
    keyid, _, raw, how = lenient_view(case)
    claimed = claimed_key(keyid, by_thumb, lenient_keyid)
    if lenient_keyid and claimed is not None and claimed["thumbprint"] != keyid:
        how = how + ["keyid decoded leniently"]
    msg = case.get("signature_base", "").encode()
    if len(raw) != 64:
        try:
            raw, how = der_to_raw(raw), how + ["DER"]
        except (ValueError, OverflowError):
            prefix = claimed is not None and sign_raw(claimed["private"], msg).startswith(raw)
            return False, None, claimed, how + [f"{len(raw)} bytes" + (f", a prefix of {claimed['name']}'s RFC 6979 signature" if prefix else "")]
    signer = next((k for k in by_thumb.values() if verify_raw(k["public"], msg, raw)), None)
    if signer:
        check_deterministic(f"{case['name']} (over its signature_base)", signer["private"], msg, raw)
    return signer is not None and signer is claimed, signer and signer["name"], claimed, how


def relax_chain(case, registry, by_thumb, derived):
    """Bypass each failing step in turn, as a verifier missing it would, until the request passes or cannot go on."""
    pubs = {t: k["public"] for t, k in by_thumb.items()}
    relax, chain = set(), []
    while True:
        out = evaluate(case, registry, set(), relax=frozenset(relax), keys=pubs, derived=derived)
        if out.rule in relax:  # a bypassed rule that still cannot go on
            chain[-1] = out
            return chain
        chain.append(out)
        if out.code == "ok" or out.rule not in RELAXABLE:
            return chain
        relax.add(out.rule)


def every_label_verifies(case, by_thumb, derived):
    """For each labelled signature, whether it verifies over its own base under its own keyid."""
    h = {k.lower(): v for k, v in case["headers"].items()}
    try:
        inputs, sigs = dict(parse_dictionary(h["signature-input"])), dict(parse_dictionary(h["signature"]))
    except (KeyError, SFError):
        return []
    result = []
    for label, (inner, params) in inputs.items():
        k = by_thumb.get(dict(params).get("keyid"))
        try:
            base = signature_base(case, h, inner, list(dict(params).items()), derived)
            result.append(k is not None and label in sigs and verify_raw(k["public"], base.encode(), b64_lenient(sigs[label][0].text)))
        except (Reject, ValueError, TypeError, AttributeError):
            result.append(False)
    return result


def check_negative(case, out, registry, by_thumb):
    name, expected, desc = case["name"], case["expected"], case.get("description", "")
    intended = intended_steps(case)
    if intended and out.step is not None:
        check(out.step in intended, f"{name}: rejected at step {out.step} ({out.rule}: {out.detail}), "
                                    f"but its description names step {'/'.join(map(str, sorted(intended)))}")
    derived = derived_components(case)
    chain = relax_chain(case, registry, by_thumb, derived)
    claimed_ok, signer, claimed, how = stated_signature(case, by_thumb, lenient_keyid=out.rule == "keyid-format")
    keyid = lenient_view(case)[0]
    iso = ["chain " + " > ".join(short(o) for o in chain)]
    claims = claimed["name"] if claimed else (keyid or "no keyid")
    iso.append((f"base signed by {signer}" + (" (claimed)" if claimed_ok else f" (claims {claims})")) if signer else "base: no test key verifies")
    iso += how + [f"{d} from signature_base" for d in derived]
    labels = every_label_verifies(case, by_thumb, derived)
    if len(labels) > 1:
        iso.append(f"{labels.count(True)}/{len(labels)} labelled signatures verify")
        check(all(labels), f"{name}: not every labelled signature verifies, so a verifier choosing another label rejects it at step 5")
    if out.step is not None and out.step < 5:
        if expected == SI or re.search(r"\b(correctly|validly) signed\b", desc):
            check(claimed_ok or (claimed is None and signer), f"{name}: rejected at step {out.step}, but its signature "
                  f"does not verify over its signature_base under the key it claims, so step 5 would reject it too")
        late = [o for o in chain[1:] if o.step == 5]
        bypassed = sorted({o.step for o in chain if o.step and o.step < 5})
        steps = f"step{'s' if len(bypassed) > 1 else ''} {' and '.join(map(str, bypassed))}"
        check(not late, f"{name}: with {steps} bypassed it still fails at step 5 ({late[0].detail if late else ''}), "
                        f"so a verifier missing {steps} would reject it for the wrong reason")
    if "checked first" in desc:
        want = sorted(ORDER_WORDS[w] for w in ORDER_WORDS if re.search(rf"\b{w}\b", desc.split(":")[0], re.I))
        got = [(o.step, o.code) for o in chain[:len(want)]]
        check(len(want) > 1 and got == want, f"{name}: ordering chain {got}, want {want}")
    return "; ".join(iso)


def check_positive(case, registry, by_thumb):
    name = case["name"]
    trace = {}
    evaluate(case, registry, set(), trace=trace)
    check(trace.get("base") == case["signature_base"], f"{name}: recomputed signature base differs from the vector")
    claimed_ok = stated_signature(case, by_thumb)[0]
    check(claimed_ok, f"{name}: signature does not verify under the claimed key")
    params = dict(dict(parse_dictionary(case["headers"]["signature-input"]))["sig"][1])
    check(params["expires"] == params["created"] + 60, f"{name}: expires != created + 60 (section 6: the agent sets it)")
    return "positive: base, signature, RFC 6979"


def check_http(V, registry, keys, show_table):
    by_thumb = {k["thumbprint"]: k for k in keys.values()}
    cases = V["http_signature"]["cases"]
    check(len({c["name"] for c in cases}) == len(cases), "http cases: duplicate names")
    rows, n_ok = [], 0
    for case in cases:
        out = evaluate(case, registry, set())
        check(out.code == case["expected"], f"{case['name']}: evaluator returns {fmt(out)}, vector expects {case['expected']}")
        if case["expected"] == "ok":
            iso, n_ok = check_positive(case, registry, by_thumb), n_ok + 1
        else:
            iso = check_negative(case, out, registry, by_thumb)
        rows.append((case, out, iso))
    print("http ok cases verified:", n_ok)
    print(f"http cases evaluated: {len(cases)} ({len(cases) - n_ok} negative, each checked for isolation)")
    if show_table:
        print("| case | expected | result | step (rule) | named step | isolation |")
        print("|---|---|---|---|---|---|")
        for case, out, iso in rows:
            steps = "/".join(map(str, sorted(intended_steps(case) or []))) if case["expected"] != "ok" else ""
            print(f"| {case['name']} | {case['expected']} | {out.code} | {short(out) if out.step else '-'} | {steps} | {iso} |")
    return {c["name"]: c for c in cases}


def check_sequences(V, registry, by_name, show_table):
    seqs = V["http_signature"]["sequences"]
    n, rows = 0, []
    for seq in seqs:
        name = seq["name"]
        check(len(seq["steps"]) == len(seq["expected"]), f"sequence {name}: steps and expected differ in length")
        nonces, done = set(), []
        for i, (step, want) in enumerate(zip(seq["steps"], seq["expected"]), 1):
            case = by_name.get(step)
            if not check(case is not None, f"sequence {name}: unknown case {step}"):
                break
            out, alone = evaluate(case, registry, nonces), evaluate(case, registry, set())
            n += 1
            rows.append(f"| {name} #{i}: {step} | {want} | {out.code} | {short(out) if out.step else '-'} | alone: {short(alone)} |")
            check(out.code == want, f"sequence {name} step {i} ({step}): {fmt(out)}, want {want}")
            pair = lenient_view(case)[:2]
            if want != "ok" and alone.code == "ok":
                check(out.step == 6, f"sequence {name} step {i}: rejected at step {out.step}, want the replay check (step 6)")
            elif want != "ok" and any(o.code == "ok" and p == pair for p, o in done):
                notes.append(f"sequence {name} step {i} ({step}) reuses an accepted (keyid, nonce) but fails at step "
                             f"{out.step} ({out.rule}) even alone, so the nonce store does not decide it")
            if out.code == "ok" and any(o.code != "ok" for _, o in done):
                if not any(o.code != "ok" and p == pair for p, o in done):
                    notes.append(f"sequence {name} step {i}: no rejected step shares its (keyid, nonce)")
            done.append((pair, out))
    print(f"sequences evaluated: {len(seqs)} ({n} steps)")
    if show_table:
        print("| sequence step | expected | result | step (rule) | same case, empty nonce store |")
        print("|---|---|---|---|---|")
        print("\n".join(rows))


# ---------------------------------------------------------------------------- other vectors

def check_channel_proof(V, keys, by_name):
    cp = V["channel_proof"]
    domain = b"devolutions-agent-identity/v1/channel-proof"
    challenge = base64.b64decode(cp["challenge"])
    check(len(challenge) == 32, "channel proof: challenge not 32 bytes")
    nonce = cp["connect_nonce"].encode()
    msg = domain + b"\x00" + challenge + nonce
    check(msg.hex() == cp["message_hex"], "channel proof: message_hex != domain||0x00||challenge||nonce")
    connect_case = by_name[cp["connect_case"]]
    keyid, case_nonce, _, _ = lenient_view(connect_case)
    check(case_nonce == cp["connect_nonce"], "channel proof: nonce not the connect case nonce")
    device = keys[cp["device"]]
    check(keyid == device["thumbprint"], "channel proof: connect case not signed by the proof's device")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(cp["public_key_sec1"]))
    check(sec1(pub) == sec1(device["public"]), "channel proof: public_key_sec1 is not the device's key")
    others = [k for k in keys.values() if k["name"] != cp["device"]]
    for c in cp["cases"]:
        raw = base64.b64decode(c["proof"])
        got = verify_raw(pub, msg, raw)
        check(got == c["expected_valid"], f"channel proof {c['name']}: verify={got}, expected {c['expected_valid']}")
        if c["name"] == "valid":
            check_deterministic("channel proof valid", device["private"], msg, raw)
        # Isolation: the rejected proof is otherwise well formed, wherever its altered input can be rebuilt.
        elif c["name"] == "missing_separator":
            check(verify_raw(pub, domain + challenge + nonce, raw), "channel proof missing_separator: not a proof over domain||challenge||nonce")
        elif c["name"] == "wrong_key":
            check(any(verify_raw(k["public"], msg, raw) for k in others), "channel proof wrong_key: no other test key signed the message")
        elif c["name"] == "der_encoded":
            check(verify_raw(pub, msg, der_to_raw(raw)), "channel proof der_encoded: not the DER form of a valid proof")
        elif c["name"] != "empty":
            check(len(raw) == 64, f"channel proof {c['name']}: not a 64-byte r||s, so it fails for its form, not its input")
    print("channel proof cases:", len(cp["cases"]))


OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")  # 1.2.840.10045.2.1
OID_P256 = bytes.fromhex("06082a8648ce3d030107")  # 1.2.840.10045.3.1.7
OID_ECDSA_SHA256 = bytes.fromhex("06082a8648ce3d040302")  # 1.2.840.10045.4.3.2
OID_ECDSA_SHA384 = bytes.fromhex("06082a8648ce3d040303")  # 1.2.840.10045.4.3.3
OID_EXTENSION_REQUEST = bytes.fromhex("06092a864886f70d01090e")  # 1.2.840.113549.1.9.14
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CSR_VALID_SEED = b"agent-identity test vector csr.valid"
# SHA-256 of the CSR DER that csr.valid held until it was regenerated; csr.valid_with_empty_extension_request keeps it.
LEGACY_VALID_CSR_SHA256 = "356f2273ae4892c99bd9182db419a90f880958f30d56cc060f73f6e8625ee200"


def der_read(buf, i=0):
    """The DER element at buf[i]: (tag, content, end). Single-byte tags, definite minimal lengths."""
    if i + 2 > len(buf):
        raise ValueError("truncated")
    tag, n, j = buf[i], buf[i + 1], i + 2
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tag")
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or j + k > len(buf) or buf[j] == 0:
            raise ValueError("bad length")
        n, j = int.from_bytes(buf[j:j + k], "big"), j + k
        if n < 0x80:
            raise ValueError("non-minimal length")
    if j + n > len(buf):
        raise ValueError("truncated")
    return tag, buf[j:j + n], j + n


def der_items(content):
    """The elements of a constructed value: [(tag, content, raw TLV)]."""
    out, i = [], 0
    while i < len(content):
        tag, c, end = der_read(content, i)
        out.append((tag, c, content[i:end]))
        i = end
    return out


def der(tag, content):
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


def parse_csr(data):
    """RFC 2986 CertificationRequest, parsed here rather than through a library's view of it."""
    tag, body, end = der_read(data)
    parts = der_items(body)
    if tag != 0x30 or end != len(data) or [t for t, _, _ in parts] != [0x30, 0x30, 0x03]:
        raise ValueError("not SEQUENCE { info, algorithm, BIT STRING }")
    (_, info, info_der), (_, alg, _), (_, sig, _) = parts
    fields = der_items(info)
    if [t for t, _, _ in fields[:3]] != [0x02, 0x30, 0x30]:
        raise ValueError("CertificationRequestInfo is not { version, subject, subjectPKInfo, ... }")
    spki = der_items(fields[2][1])
    if [t for t, _, _ in spki] != [0x30, 0x03] or spki[1][1][:1] != b"\x00" or sig[:1] != b"\x00":
        raise ValueError("SubjectPublicKeyInfo or signature BIT STRING")
    return {"info_der": info_der, "key_alg": [raw for _, _, raw in der_items(spki[0][1])], "point": spki[1][1][1:],
            "alg": [raw for _, _, raw in der_items(alg)], "signature": sig[1:], "attributes": fields[3:]}


def stated_csr_reason(name):
    for words, rule in [(("self_signature", "self-signature"), "self-signature"),
                        (("sha1", "sha384", "sha512", "alg"), "signature algorithm"),
                        (("compressed", "curve", "p384", "key"), "key")]:
        if any(w in name.lower() for w in words):
            return rule
    return None


def check_csr_entry(name, e, layout):
    """§4 server rules for one csr entry, plus its shape; returns the problems found."""
    found = []
    deterministic = None
    def need(cond, msg):
        if not cond:
            found.append(f"csr {name}: {msg}")
        return cond
    data = base64.b64decode(e["csr"])
    try:
        f = parse_csr(data)
    except ValueError as err:
        need(e["expected"] != "ok", f"unparseable ({err}), but expected {e['expected']}")
        return found, deterministic
    point = f["point"]
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        pub = None
    digest = {OID_ECDSA_SHA256: hashes.SHA256(), OID_ECDSA_SHA384: hashes.SHA384()}.get(f["alg"][0] if len(f["alg"]) == 1 else None)
    try:
        self_signed = pub is not None and digest is not None and pub.verify(f["signature"], f["info_der"], ec.ECDSA(digest)) is None
    except (InvalidSignature, ValueError):
        self_signed = False
    rules = {"key": f["key_alg"] == [OID_EC_PUBLIC_KEY, OID_P256] and pub is not None and len(point) == 65 and point[0] == 4,
             "self-signature": self_signed,
             "signature algorithm": f["alg"] == [OID_ECDSA_SHA256]}  # RFC 5758 §3.2: parameters absent
    failing = [r for r, ok in rules.items() if not ok]
    need(("invalid_request" if failing else "ok") == e["expected"], f"section 4 gives {'invalid_request' if failing else 'ok'} "
         f"({', '.join(failing) or 'all rules pass'}), expected {e['expected']}")
    if e["expected"] != "ok":
        stated = stated_csr_reason(name)
        need(failing == [stated], f"fails {failing}, want only its stated reason ({stated})")
    if "public_key_sec1" in e:
        need(base64.b64decode(e["public_key_sec1"]) == point, "public_key_sec1 is not the CSR key")
    attrs = f["attributes"]
    if name == "valid":
        need(len(attrs) == 1 and attrs[0][2] == b"\xa0\x00" and f["info_der"].endswith(b"\xa0\x00"),
             "attribute set is not present and empty: CertificationRequestInfo ends "
             + (f"with attributes {attrs[0][2].hex()}" if attrs else "without the [0] attributes field") + ", want a000 (section 4)")
        pkcs8 = next((k for k in e if "pkcs8" in k), None)
        if pkcs8:
            key = serialization.load_der_private_key(base64.b64decode(e[pkcs8]), None)
            d = int.from_bytes(hashlib.sha256(CSR_VALID_SEED).digest(), "big") % P256_ORDER
            need(isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp256r1"
                 and key.private_numbers().private_value == d, f"{pkcs8} is not d = SHA-256({CSR_VALID_SEED.decode()!r}) mod n")
            if need(sec1(key.public_key()) == point, f"the CSR key is not the {pkcs8} key"):
                deterministic = sign_raw(key, f["info_der"]) == raw_signature(f["signature"])
                need(deterministic, "signature is not the RFC 6979 deterministic signature")
        else:
            need("valid_with_empty_extension_request" not in layout, "no PKCS#8 key stored for the regenerated CSR")
    if name == "valid_with_empty_extension_request":
        try:
            attr = der_items(attrs[0][1]) if len(attrs) == 1 and attrs[0][0] == 0xA0 else []
            fields = der_items(attr[0][1]) if len(attr) == 1 and attr[0][0] == 0x30 else []
            values = der_items(fields[1][1]) if len(fields) == 2 and fields[1][0] == 0x31 else []
        except ValueError:
            fields = values = []
        need(len(fields) == 2 and fields[0][2] == OID_EXTENSION_REQUEST and len(values) == 1 and values[0][2] == b"\x30\x00",
             "the only attribute is not extensionRequest with an empty Extensions SEQUENCE")
        need(hashlib.sha256(data).hexdigest() == LEGACY_VALID_CSR_SHA256, "not byte-identical to the former csr.valid")
    return found, deterministic


def raw_signature(sig_der):
    try:
        return der_to_raw(sig_der)
    except (ValueError, OverflowError):
        return b""


def check_csr(V):
    for name, e in V["csr"].items():
        found, deterministic = check_csr_entry(name, e, V["csr"])
        problems.extend(found)
        if deterministic is not None:
            det["total"] += 1
            det["ok"] += deterministic
    print("csr cases:", len(V["csr"]))


def check_rfc9421_b_2_4(V):
    b = V["rfc9421_b_2_4"]
    bpub = serialization.load_der_public_key(base64.b64decode(b["public_key_spki"]))
    braw = base64.b64decode(b.get("signature") or b["signature_header"].split(":")[1])
    check(verify_raw(bpub, b["signature_base"].encode(), braw) == b.get("expected_valid", True), "RFC 9421 B.2.4 does not verify")
    print("rfc9421 B.2.4 base first line:", b["signature_base"].splitlines()[0])


# ---------------------------------------------------------------------------- self-test

def mutate(case, label, changes):
    m = json.loads(json.dumps(case))
    m["name"] = f"{case['name']} / {label}"
    for k, v in changes.items():
        if v is None:
            m["headers"].pop(k, None)
        else:
            m["headers"][k] = v
    return m


def resign(m, registry, by_thumb, relax, signer=None):
    """Sign `m` over the base that a verifier bypassing `relax` builds, so that only those rules reject it."""
    keyid = lenient_view(m)[0]
    signer = signer or by_thumb.get(keyid)
    trace = {}
    later = {"tag", "window", "keyid", "revoked", "validity", "digest", "signature"}  # never change the base
    evaluate(m, registry, set(), relax=frozenset(relax) | later, keys={keyid: signer and signer["public"]}, trace=trace)
    if check(signer and "base" in trace, f"self-test {m['name']}: no base or key to re-sign with"):
        m["headers"]["signature"] = f"sig=:{b64(sign_raw(signer['private'], trace['base'].encode()))}:"
    return m


def with_pad_bit(text, alphabet=B64_ALPHABET):
    """`text` with its lowest pad bit set, which a lenient decoder ignores."""
    data = text.rstrip("=")
    assert len(data) % 4 in (2, 3), "no pad bits"
    return data[:-1] + alphabet[alphabet.index(data[-1]) | 1] + text[len(data):]


def set_param(si, name, raw):
    return re.sub(rf';{name}=("[^"]*"|[^;,]*)', lambda _: f";{name}={raw}", si, count=1)


def mutations(case, registry, by_thumb):
    """(label, step-1 rule, outcome with that rule bypassed or None, request) built from positive `case`."""
    h = case["headers"]
    si, sg = h["signature-input"], h["signature"]
    sig = sg[len("sig=:"):-1]
    keyid, nonce, _, _ = lenient_view(case)
    signer = by_thumb[keyid]
    tag = OPERATIONS[case["endpoint"]][0]
    other_tag = "renew" if tag == "connect" else "connect"
    other_nonce = b64u(hashlib.sha256(nonce.encode()).digest()[:16])
    other_member = si.replace(f'nonce="{nonce}"', f'nonce="{other_nonce}"')
    raw_nonce = base64.urlsafe_b64decode(nonce + "==")
    created = re.search(r"created=(\d+)", si).group(1)
    expires = re.search(r"expires=(\d+)", si).group(1)
    out = []

    def add(label, rule, changes, resign_relaxing=None, relaxed="ok"):
        m = mutate(case, label, changes)
        out.append((label, rule, relaxed, resign(m, registry, by_thumb, resign_relaxing, signer) if resign_relaxing else m))

    add("Signature: non-zero pad bits", "b64", {"signature": f"sig=:{with_pad_bit(sig)}:"})
    add("Signature: padding missing", "b64", {"signature": f"sig=:{sig.rstrip('=')}:"})
    add("Signature: repeated label", "dup", {"signature": f"sig=:{b64(bytes(range(64)))}:, {sg}"})
    add("Signature: repeated label, same value", "dup", {"signature": f"{sg}, {sg}"})
    add("Signature-Input: repeated label", "dup", {"signature-input": f"{other_member}, {si}"}, {"dup"})
    add("Signature-Input: repeated label, original first", "dup", {"signature-input": f"{si}, {other_member}"}, {"dup"})
    add("tag repeated", "dup", {"signature-input": f'{si};tag="{tag}"'}, {"dup"})
    add("tag repeated, another tag first", "dup", {"signature-input": si.replace(f'tag="{tag}"', f'tag="{other_tag}";tag="{tag}"')}, {"dup"})
    add("nonce repeated", "dup", {"signature-input": f'{si};nonce="{other_nonce}"'}, {"dup"})
    # keyid is a thumbprint (§1, §6 step 1). A verifier that normalizes keyids would accept the first three;
    # without the check, the last two would draw the terminal identity_unknown that step 1 exists to prevent.
    for label, bad, relaxed in [("keyid padded", keyid + "=", "ok"),
                                ("keyid in the standard alphabet", keyid.replace("-", "+").replace("_", "/"), "ok"),
                                ("keyid with non-zero pad bits", with_pad_bit(keyid, URL_ALPHABET), "ok"),
                                ("keyid truncated", keyid[:-1], "identity_unknown"),
                                ("keyid as a hex digest", base64.urlsafe_b64decode(keyid + "=").hex(), "identity_unknown")]:
        if bad != keyid:
            add(label, "keyid-format", {"signature-input": set_param(si, "keyid", f'"{bad}"')}, {"keyid-format"}, relaxed)
    for label, bad in [("nonce padded", nonce + "=="), ("nonce of 15 bytes", b64u(raw_nonce[:15])),
                       ("nonce of 17 bytes", b64u(raw_nonce + b"\0")), ("nonce empty", ""),
                       ("nonce with non-zero pad bits", with_pad_bit(nonce, URL_ALPHABET)),
                       ("nonce in the standard alphabet", nonce.replace("-", "+").replace("_", "/"))]:
        if bad != nonce:
            add(label, "nonce-format", {"signature-input": set_param(si, "nonce", f'"{bad}"')}, {"nonce-format"})
    # Wrong RFC 8941 types, each accepted by a verifier that ignores types.
    for label, name, raw in [("created as a string", "created", f'"{created}"'), ("expires as a string", "expires", f'"{expires}"'),
                             ("created as a decimal", "created", f"{created}.0"), ("alg as a token", "alg", ALG),
                             ("tag as a token", "tag", tag), ("keyid as a byte sequence", "keyid", f":{b64(keyid.encode())}:"),
                             ("nonce as a token", "nonce", nonce if nonce[0].isalpha() else None)]:
        if raw is not None:
            add(label, "param-type", {"signature-input": set_param(si, name, raw)}, {"param-type"})
    for raw in [";x=1", ";x", f';alg="{ALG}"']:
        add(f"Signature member parameter {raw}", "member-param", {"signature": sg + raw})
    if "content-digest" in OPERATIONS[case["endpoint"]][1]:
        cd = h["content-digest"]
        d = cd[len("sha-256=:"):-1]
        add("Content-Digest: non-zero pad bits", "b64", {"content-digest": f"sha-256=:{with_pad_bit(d)}:"}, {"b64"})
        add("Content-Digest: padding missing", "b64", {"content-digest": f"sha-256=:{d.rstrip('=')}:"}, {"b64"})
        wrong = b64(hashlib.sha256(b"other").digest())
        add("Content-Digest: repeated sha-256 member", "dup", {"content-digest": f"sha-256=:{wrong}:, {cd}"}, {"dup"})
        add("Content-Digest: repeated sha-256 member, same value", "dup", {"content-digest": f"{cd}, {cd}"}, {"dup"})
        add("Content-Digest: missing", "digest-member", {"content-digest": None}, relaxed=None)
        for raw in [";x=1", ";x"]:
            add(f"Content-Digest member parameter {raw}", "digest-param", {"content-digest": cd + raw}, {"digest-param"})
        for raw in [";sf", ';key="sha-256"']:  # RFC 9421 §2.1.1 and §2.1.2 give these a value
            add(f'covered component "content-digest"{raw}', "component-param",
                {"signature-input": si.replace('"content-digest"', f'"content-digest"{raw}', 1)}, {"component-param"})
    # No RFC 9421 parameter applies to @method in a request, so a lenient verifier has no base to accept it with.
    add('covered component "@method";req', "component-param", {"signature-input": si.replace('"@method"', '"@method";req', 1)}, relaxed=None)
    add("Signature-Input trailing comma", "parse", {"signature-input": si + ","}, relaxed=None)
    if "+" in sig or "/" in sig:
        add("Signature in the base64url alphabet", "parse", {"signature": f"sig=:{sig.replace('+', '-').replace('/', '_')}:"}, relaxed=None)
    return out


def unit_tests():
    for text, want in [("", b""), ("AA==", b"\0"), ("AAE=", b"\0\1"), ("AAEC", b"\0\1\2")]:
        check(b64_canonical(text) == want, f"self-test: b64_canonical({text!r})")
    for text, why in [("AB==", "pad bits"), ("AAF=", "pad bits"), ("AA", "padding missing"), ("AAE", "padding missing"),
                      ("AA=", "wrong padding"), ("A===", "wrong padding"), ("AA==AA==", "alphabet"), ("AA-_", "alphabet")]:
        try:
            b64_canonical(text)
            problems.append(f"self-test: b64_canonical accepts {text!r}")
        except ValueError as e:
            check(why in str(e), f"self-test: b64_canonical({text!r}) fails with {e}, want {why}")
    check(b64_lenient("AB") == b"\0" and b64_lenient("AAF") == b"\0\1", "self-test: b64_lenient")
    m = parse_dictionary('a=1, a=2;x;x=?0,  b=("s" tok :AA==:);p=-1.5, c')
    check([k for k, _ in m] == ["a", "a", "b", "c"], "self-test: parser loses a repeated member")
    check(m[1][1][1] == [("x", True), ("x", False)], "self-test: parser loses a repeated parameter")
    check(ser_inner_list(*m[2][1]) == '("s" tok :AA==:);p=-1.5', "self-test: inner list round trip")
    check(parse_dictionary('k="a\\"b\\\\"')[0][1][0] == 'a"b\\', "self-test: string escapes")
    check([k for k, _ in parse_dictionary("a=1,\tb=2 ")] == ["a", "b"], "self-test: OWS around a comma")
    check(is_b64url("AAECAwQFBgcICQoLDA0ODw", 16) and not is_b64url("AAECAwQFBgcICQoLDA0ODx", 16)
          and not is_b64url("AAECAwQFBgcICQoLDA0ODw==", 16) and not is_b64url("AAECAwQFBgcICQoLDA0O", 16), "self-test: is_b64url")
    for bad in ["A=1", "a=1,", "a=1 b=2", "a=(1", 'a="\\x"', "a=:AA", "a=1;", "a=?2", "a=1 ,", "a=(1)x", "a=\u00e9", 'a="\t"', "\ta=1"]:
        try:
            parse_dictionary(bad)
            problems.append(f"self-test: parser accepts {bad!r}")
        except SFError:
            pass


def boundary_tests(V, registry, by_thumb):
    """Validity edges (§6): now == notAfter is unexpired; renew grace ends at notAfter + lifetime."""
    firsts = {}
    for c in V["http_signature"]["cases"]:
        if c["expected"] == "ok":
            firsts.setdefault(c["endpoint"], c)
    n = 0
    for endpoint, case in firsts.items():
        cert = registry[lenient_view(case)[0]]
        na, nb = cert["not_after"], cert["not_before"]
        edges = ([(na, "ok"), (2 * na - nb - 1, "ok"), (2 * na - nb, "certificate_expired")] if endpoint == "renew"
                 else [(na, "ok"), (na + 1, "certificate_expired")])
        for now, want in edges:
            si = re.sub(r"expires=\d+", f"expires={now + 60}", re.sub(r"created=\d+", f"created={now}", case["headers"]["signature-input"]))
            m = mutate(case, f"now={now} (notAfter{now - na:+d})", {"signature-input": si})
            m["now"] = now
            out = evaluate(resign(m, registry, by_thumb, set()), registry, set())
            n += 1
            check(out.code == want and out.step in (None, 4), f"self-test {m['name']} [{cert['name']}]: {fmt(out)}, want {want}")
    return n


def build_csr(key, attributes=b"\xa0\x00", alg=OID_ECDSA_SHA256, compressed=False, corrupt=False):
    """A PKCS#10 CSR assembled from DER by hand and signed deterministically by `key`."""
    fmt_ = serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint
    point = key.public_key().public_bytes(serialization.Encoding.X962, fmt_)
    spki = der(0x30, der(0x30, OID_EC_PUBLIC_KEY + OID_P256) + der(0x03, b"\x00" + point))
    subject = der(0x30, der(0x31, der(0x30, bytes.fromhex("0603550403") + der(0x0C, b"ignored"))))
    info = der(0x30, b"\x02\x01\x00" + subject + spki + attributes)
    sig = key.sign(info, ec.ECDSA(hashes.SHA384() if alg == OID_ECDSA_SHA384 else hashes.SHA256(), deterministic_signing=True))
    if corrupt:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    return der(0x30, info + der(0x30, alg) + der(0x03, b"\x00" + sig))


def csr_self_test(V):
    """Run the csr checks on the announced layout, which must pass, and on mutations, which each must fail."""
    d = int.from_bytes(hashlib.sha256(CSR_VALID_SEED).digest(), "big") % P256_ORDER
    key, other = ec.derive_private_key(d, ec.SECP256R1()), ec.derive_private_key(d + 1, ec.SECP256R1())

    def entry(csr, k=key, expected="ok"):
        pkcs8 = k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return {"csr": b64(csr), "public_key_sec1": b64(sec1(k.public_key())), "private_key_pkcs8": b64(pkcs8), "expected": expected}

    csrs = V["csr"]
    legacy = csrs.get("valid_with_empty_extension_request", csrs["valid"])
    layout = {"valid": entry(build_csr(key)), "valid_with_empty_extension_request": legacy,
              "bad_self_signature": csrs["bad_self_signature"], "ecdsa_with_sha384": csrs["ecdsa_with_sha384"]}
    accepted = [p for n, e in layout.items() for p in check_csr_entry(n, e, layout)[0]]
    check(not accepted, f"self-test csr: the announced layout is rejected: {accepted}")

    def ext_request(extensions):
        return der(0xA0, der(0x30, OID_EXTENSION_REQUEST + der(0x31, der(0x30, extensions))))
    key_usage = der(0x30, bytes.fromhex("0603551d0f") + der(0x04, bytes.fromhex("03020780")))
    other_attribute = der(0x30, bytes.fromhex("06092a864886f70d010907") + der(0x31, der(0x30, b"")))  # challengePassword OID
    two_attributes = der(0xA0, ext_request(b"")[2:] + other_attribute)
    unkeyed = {k: v for k, v in entry(build_csr(key)).items() if k != "private_key_pkcs8"}
    mutations_ = [
        ("valid", "[0] attributes omitted", entry(build_csr(key, attributes=b"")), "attribute set is not present and empty"),
        ("valid", "empty extensionRequest", entry(build_csr(key, attributes=ext_request(b""))), "attribute set is not present and empty"),
        ("valid", "ecdsa-with-SHA384", entry(build_csr(key, alg=OID_ECDSA_SHA384)), "(signature algorithm)"),
        ("valid", "bad self-signature", entry(build_csr(key, corrupt=True)), "(self-signature)"),
        ("valid", "compressed point", entry(build_csr(key, compressed=True)), "(key)"),
        ("valid", "another key", entry(build_csr(other), other), "is not d = SHA-256"),
        ("valid", "no PKCS#8 key", unkeyed, "no PKCS#8 key stored"),
        ("valid_with_empty_extension_request", "one extension", entry(build_csr(key, attributes=ext_request(key_usage))), "the only attribute"),
        ("valid_with_empty_extension_request", "another attribute type", entry(build_csr(key, attributes=der(0xA0, other_attribute))), "the only attribute"),
        ("valid_with_empty_extension_request", "a second attribute", entry(build_csr(key, attributes=two_attributes)), "the only attribute"),
        ("valid_with_empty_extension_request", "regenerated", entry(build_csr(key, attributes=ext_request(b""))), "byte-identical"),
        ("bad_self_signature", "also SHA-384", entry(build_csr(key, alg=OID_ECDSA_SHA384, corrupt=True), expected="invalid_request"), "only its stated reason"),
        ("ecdsa_with_sha384", "bad self-signature instead", entry(build_csr(key, corrupt=True), expected="invalid_request"), "only its stated reason"),
    ]
    for name, label, e, want in mutations_:
        found = check_csr_entry(name, e, layout)[0]
        check(any(want in p for p in found), f"self-test csr {name} / {label}: want a problem with {want!r}, got {found}")
    return len(layout), len(mutations_)


def self_test(V, registry, keys):
    unit_tests()
    by_thumb = {k["thumbprint"]: k for k in keys.values()}
    positives = [c for c in V["http_signature"]["cases"] if c["expected"] == "ok"]
    n = isolated = 0
    per_rule = {}
    for case in positives:
        check(evaluate(case, registry, set()).code == "ok", f"self-test: {case['name']} is not ok before mutation")
        for label, rule, relaxed, m in mutations(case, registry, by_thumb):
            n += 1
            per_rule[rule] = per_rule.get(rule, 0) + 1
            out = evaluate(m, registry, set())
            check((out.code, out.step, out.rule) == (SI, 1, rule), f"self-test {m['name']}: {fmt(out)}, want {SI} at step 1 ({rule})")
            if relaxed:
                isolated += 1
                rel = evaluate(m, registry, set(), relax=frozenset({rule}))
                check(rel.code == relaxed and rel.step in (None, 4), f"self-test {m['name']}: with {rule} bypassed {fmt(rel)}, want {relaxed}")
        # Control: legal RFC 8941 whitespace changes nothing, since @signature-params is re-serialized.
        si = case["headers"]["signature-input"]
        spaced = si.replace("(", "( ").replace(")", " )").replace('" "', '"  "').replace(";", "; ")
        m, trace = mutate(case, "whitespace", {"signature-input": spaced}), {}
        out = evaluate(m, registry, set(), trace=trace)
        check(out.code == "ok" and trace.get("base") == case["signature_base"], f"self-test {m['name']}: {fmt(out)}, want ok and the same base")
    print(f"self-test: {n} step-1 mutations of {len(positives)} positive cases ({isolated} also checked for isolation), "
          f"{len(positives)} whitespace controls")
    print("self-test mutations per rule:", ", ".join(f"{r} {k}" for r, k in sorted(per_rule.items())))
    print(f"self-test validity boundaries: {boundary_tests(V, registry, by_thumb)}")
    print("self-test csr: announced layout of {} entries accepted, {} mutations rejected".format(*csr_self_test(V)))


# ---------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Recompute the Agent Identity test vectors independently.")
    ap.add_argument("path", nargs="?", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-vectors.json"))
    ap.add_argument("--self-test", action="store_true", help="check the evaluator against step-1 mutations of the positive cases")
    ap.add_argument("--table", action="store_true", help="print one row per http_signature case")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    with open(args.path, encoding="utf-8") as f:
        V = json.load(f)
    registry, keys = check_material(V)
    if args.self_test:
        self_test(V, registry, keys)
    else:
        by_name = check_http(V, registry, keys, args.table)
        check_sequences(V, registry, by_name, args.table)
        check_channel_proof(V, keys, by_name)
        check_csr(V)
        check_rfc9421_b_2_4(V)
        print(f"deterministic RFC 6979 reproduced: {det['ok']}/{det['total']}")
    for n in notes:
        print("note:", n)
    print("PROBLEMS:" if problems else "ALL CHECKS PASSED")
    for p in problems:
        print(" -", p)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
