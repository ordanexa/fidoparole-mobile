#!/usr/bin/env python3
"""Cross-check the Rust CTAP2 code against Yubico's python-fido2.

python-fido2 (an independent CTAP2 client) talks to the Rust mock
authenticator, and both clients read each other's data:
  * PIN tokens with permissions, PIN/UV protocols 1 and 2
  * makeCredential with hmac-secret, credProtect, largeBlobKey (rk)
  * getAssertion with an hmac-secret salt; output must equal the Rust client's
  * largeBlobs written by python are found by Rust, and vice versa
  * credential deletion via credentialManagement

Usage: pip install fido2; cargo build --example mock_server --features mock
       python3 tools/crosscheck.py target/debug/examples/mock_server
"""
import hashlib, json, os, struct, subprocess, sys

from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID

PIN = "123456"
RP = "fido2-vault.token2"
PRF_INPUT = b"Token2 fido2-vault v1 / hmac-secret salt"
SALT = hashlib.sha256(b"WebAuthn PRF\x00" + PRF_INPUT).digest()


class MockDevice(CtapDevice):
    def __init__(self, exe, protocols):
        self.p = subprocess.Popen([exe, protocols], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def raw(self, cmd, payload=b""):
        self.p.stdin.write(bytes([cmd]) + struct.pack(">I", len(payload)) + payload)
        self.p.stdin.flush()
        n = struct.unpack(">I", self.p.stdout.read(4))[0]
        return self.p.stdout.read(n)

    @property
    def version(self): return 2
    @property
    def capabilities(self): return CAPABILITY.CBOR
    def close(self): self.p.stdin.close(); self.p.wait()

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        return self.raw(data[0], data[1:])

    @classmethod
    def list_devices(cls): return iter([])


def run(exe, protocols, proto):
    dev = MockDevice(exe, protocols)
    ctap = Ctap2(dev)
    cp = ClientPin(ctap, proto)
    P = ClientPin.PERMISSION

    # python creates a vault-style credential
    tok = cp.get_pin_token(PIN, P.MAKE_CREDENTIAL, RP)
    cdh = os.urandom(32)
    user_id = b"\x01" + os.urandom(8) + b"PyVault"
    att = ctap.make_credential(
        cdh, {"id": RP, "name": "FidoParole"}, {"id": user_id, "name": "PyVault", "displayName": "PyVault"},
        [{"type": "public-key", "alg": -7}],
        extensions={"hmac-secret": True, "credProtect": 3, "largeBlobKey": True},
        options={"rk": True}, pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
    cred_id = att.auth_data.credential_data.credential_id
    lbk = att.large_blob_key
    assert lbk and len(lbk) == 32, "largeBlobKey missing"
    assert att.auth_data.extensions.get("hmac-secret") is True

    # python asserts with the vault salt
    tok = cp.get_pin_token(PIN, P.GET_ASSERTION | P.LARGE_BLOB_WRITE, RP)
    key_agreement, shared = cp._get_shared_secret()
    salt_enc = proto.encrypt(shared, SALT)
    ext = {"hmac-secret": {1: key_agreement, 2: salt_enc, 3: proto.authenticate(shared, salt_enc), 4: proto.VERSION},
           "largeBlobKey": True}
    cdh = os.urandom(32)
    a = ctap.get_assertion(RP, cdh, [{"type": "public-key", "id": cred_id}], ext,
                           pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
    py_hmac = proto.decrypt(shared, a.auth_data.extensions["hmac-secret"])[:32]
    assert a.large_blob_key == lbk

    # python writes a largeBlob (lbw permission survived the assertion)
    LargeBlobs(ctap, proto, tok).put_blob(lbk, b"hello from python-fido2")

    # Rust unlocks: same hmac-secret, finds python's blob
    r = json.loads(dev.raw(0xFE))
    v = [x for x in r["vaults"] if x["cred_id"] == cred_id.hex()]
    assert v, r
    assert v[0]["name"] == "PyVault", v[0]
    assert v[0]["hmac"] == py_hmac.hex(), "hmac-secret differs between python-fido2 and Rust"
    assert bytes.fromhex(v[0]["blob"]) == b"hello from python-fido2"

    # Rust creates a vault; python reads its largeBlob
    rv = json.loads(dev.raw(0xFD))
    tok = cp.get_pin_token(PIN, P.LARGE_BLOB_WRITE)
    blob = LargeBlobs(ctap, proto, tok).get_blob(bytes.fromhex(rv["lbk"]))
    assert blob and blob.startswith(b"T2VLT"), blob
    # python's entry is still intact next to Rust's
    assert LargeBlobs(ctap, proto, tok).get_blob(lbk) == b"hello from python-fido2"

    # python deletes its credential; Rust sees only RustVault
    tok = cp.get_pin_token(PIN, P.CREDENTIAL_MGMT)
    CredentialManagement(ctap, proto, tok).delete_cred({"type": "public-key", "id": cred_id})
    names = [x["name"] for x in json.loads(dev.raw(0xFE))["vaults"]]
    assert names == ["RustVault"], names

    # wrong PIN is rejected with PIN_INVALID
    try:
        cp.get_pin_token("000000", P.GET_ASSERTION, RP)
        raise AssertionError("wrong PIN accepted")
    except CtapError as e:
        assert e.code == CtapError.ERR.PIN_INVALID
    dev.close()


if __name__ == "__main__":
    exe = sys.argv[1]
    run(exe, "2,1", PinProtocolV2())
    run(exe, "1", PinProtocolV1())
    print("cross-check OK: python-fido2 and the Rust client agree (PIN protocols 1 and 2)")
