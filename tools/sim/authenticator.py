# Independent CTAP simulator (python-fido2 + cryptography), contributed by Pascal
# (FidoParole Reader for Android). Used by core/examples/sim_check.rs:
#   pip install -r tools/sim/requirements.txt
#   cargo run -p fidoparole-core --features mock --example sim_check -- tools/sim/authenticator.py
# Relaxed vs. the original: the "up" option and the hmac-secret protocol field
# are optional (CTAP 2.1 defaults), as real keys accept.
"""Independent CTAP simulator using python-fido2 and cryptography, no USB hardware.
All credentials and PINs below are dummy fixtures. stdout is only the wire protocol.
"""
import sys, os, hashlib, hmac, json, zlib, struct
from fido2 import cbor
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

mode = sys.argv[1]
version = 1 if mode == 'v1' else 2
proto = PinProtocolV1() if version == 1 else PinProtocolV2()
RP = 'fido2-vault.token2'
PIN = b'123456'
secret = bytes(range(32))
blob_key = bytes(range(32, 64))
token = b'T' * 32
priv = None
agreement = None
assertions = 0
pin_attempts = 0

def deflate(data):
    z = zlib.compressobj(wbits=-15)
    return z.compress(data) + z.flush()

def hkdf(z, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(z)

def vault_blob():
    obj = {'v': 2, 'e': [{'i':'dummy001','t':'Vaultwarden','u':'pascal','p':'dummy-copy-password'}]}
    if mode == 'format1':
        obj = {'version':1,'entries':[{'id':'dummy001','title':'Vaultwarden','username':'pascal','password':'dummy-copy-password'}]}
    salt, nonce = b'S'*16, b'N'*12
    header = b'T2VLT\x01' + salt + nonce
    key = hkdf(secret, salt, b'Token2 fido2-vault v1 / AES-256-GCM')
    return header + AESGCM(key).encrypt(nonce, deflate(json.dumps(obj).encode()), header)

blob = vault_blob()
if mode == "vault_tamper": blob = blob[:-1] + bytes([blob[-1] ^ 1])
nonce = b'B'*12
entry = {1:AESGCM(blob_key).encrypt(nonce, deflate(blob), b'blob'+struct.pack('<Q',len(blob))),2:nonce,3:len(blob)}
# Nonmatching entry forces both multi-fragment reads and AEAD key selection.
array = cbor.encode([{1:b'X'*1200,2:b'Z'*12,3:12}, entry])
array += hashlib.sha256(array).digest()[:16]
if mode == 'checksum': array = array[:-1] + bytes([array[-1] ^ 1])

def assertion():
    flags = 0x81 if mode == 'no_uv' else 0x85
    ad = hashlib.sha256(RP.encode()).digest()+bytes([flags])+b'\0'*4+cbor.encode({'hmac-secret':proto.encrypt(agreement,b'W'*32 if mode=='wrong_secret' else secret)})
    return {1:{'id':b'credential-id','type':'public-key'},2:ad,3:b'dummy-signature',4:{'id':b'\x01'+b'01234567'+b'Test vault'},5:2,7:blob_key}

def respond(raw):
    global priv, agreement, assertions, pin_attempts
    cmd = raw[0]
    args = cbor.decode(raw[1:]) if len(raw)>1 else {}
    if cmd == 4:
        return {1:['FIDO_2_1'],2:['hmac-secret','largeBlobKey'],3:b'A'*16,4:{'clientPin':True,'largeBlobs':True,'pinUvAuthToken':version==2},5:1024,6:[version]}
    if cmd == 6:
        assert args[1] == version
        sub = args[2]
        if sub == 1: return {3:2 if mode=='low_retries' else 8}
        if sub == 2:
            priv=ec.generate_private_key(ec.SECP256R1());p=priv.public_key().public_numbers()
            return {1:{1:2,3:-25,-1:1,-2:p.x.to_bytes(32,'big'),-3:p.y.to_bytes(32,'big')}}
        assert sub == (9 if version==2 else 5), 'forbidden PIN subcommand'
        if version == 2: assert args[9] == 2 and args[10] == RP
        pin_attempts += 1
        assert pin_attempts == 1, 'automatic PIN retry'
        peer=args[3]
        pk=ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2],'big'),int.from_bytes(peer[-3],'big'),ec.SECP256R1()).public_key()
        shared=proto.kdf(priv.exchange(ec.ECDH(),pk))
        assert proto.decrypt(shared,args[6]) == hashlib.sha256(PIN).digest()[:16]
        if mode=='wrong_pin': return 0x31
        return {2:proto.encrypt(shared,token)}
    if cmd == 2:
        assert args[1]==RP and args.get(5,{'up':True})=={'up':True}
        assert hmac.compare_digest(args[6],proto.authenticate(token,args[2]))
        ext=args[4]
        assert ext['largeBlobKey'] is True
        hs=ext['hmac-secret']; assert hs.get(4,1)==version
        peer=hs[1]
        pk=ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2],'big'),int.from_bytes(peer[-3],'big'),ec.SECP256R1()).public_key()
        agreement=proto.kdf(priv.exchange(ec.ECDH(),pk))
        assert hmac.compare_digest(hs[3],proto.authenticate(agreement,hs[2]))
        assert proto.decrypt(agreement,hs[2]) == hashlib.sha256(b'WebAuthn PRF\0Token2 fido2-vault v1 / hmac-secret salt').digest()
        assertions=1
        return assertion()
    if cmd==8:
        assert assertions==1;assertions+=1
        return assertion()
    if cmd==12:
        assert assertions==2, 'getNextAssertion must precede blob reads'
        assert set(args)=={1,3}, 'largeBlob writes forbidden'
        return {1:array[args[3]:args[3]+args[1]]}
    raise AssertionError('Forbidden CTAP command')

for line in sys.stdin:
    try:
        result=respond(bytes.fromhex(line.strip()))
        print((bytes([result]) if isinstance(result,int) else b'\0'+cbor.encode(result)).hex(),flush=True)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
