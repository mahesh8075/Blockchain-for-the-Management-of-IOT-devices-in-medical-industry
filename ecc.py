from ecdsa import SigningKey

global private_key, public_key

#generate ecc keys
def generateECCKey():
    global private_key, public_key
    private_key = SigningKey.generate()
    public_key = private_key.verifying_key

def eccSign(msg):
    global private_key, public_key
    signature = private_key.sign(msg)
    return signature

def eccVerify(signature, msg):
    global private_key, public_key
    return public_key.verify(signature, msg)