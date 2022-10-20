import requests
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from binascii import unhexlify

class ACMEClient(object):

    def __init__(self, dir) -> None:
        self.dir = dir
        self.urls = {}
        self.nonce = None
        self.privateKey = None
        self.publicKey = None
        self.accountUrl = None
        self.finalize = None
        self.authorizations = []
        self.chalUrl = None
        self.token = None
        self.getPrivateKey()
        self.getPublicKey()

    def firstRequest(self):
        res = requests.get(self.dir, verify='pebble.minica.pem')
        return res
    
    def setupUrls(self):
        js = self.firstRequest().json()
        for item in js:
            self.urls[item] = js[item]

    def getNonce(self):
        res = requests.head(self.urls['newNonce'], verify='pebble.minica.pem')
        self.nonce = res.headers['Replay-Nonce']

    def getPrivateKey(self):
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    def getPublicKey(self):
        self.publicKey = self.privateKey.public_key().public_numbers()

    def createAccount(self):
        data = {'protected':None, 'payload':None, 'signature':None}
        protected = {}
        protected['alg'] = 'RS256'
        protected['nonce'] = self.nonce
        protected['url'] = self.urls['newAccount']

        payload = {}
        payload['termsOfServiceAgreed'] = True
        data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

        exp = f"{self.publicKey.e:x}"
        mod = f"{self.publicKey.n:x}"

        if len(exp) % 2:
            exp = f"0{exp}"
        if len(mod) % 2:
            mod = f"0{mod}"
        protected['jwk'] = {'kty':'RSA', 'e':base64.urlsafe_b64encode(unhexlify(exp)).rstrip(b"=").decode('utf-8'),
            'n':base64.urlsafe_b64encode(unhexlify(mod)).rstrip(b"=").decode('utf-8')}
        
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')
        sig = data['signature']

        headers = {'Content-type': 'application/jose+json'}

        res = requests.post(self.urls['newAccount'], headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print(res.status_code, res.content, res.headers)
        self.accountUrl = res.headers['Location']
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()

    def submitOrder(self, domains):
        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.urls['newOrder']
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

        payload = {}
        payload['identifiers'] = [{'type':'dns', 'value':domain} for domain in domains]
        data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}

        res = requests.post(self.urls['newOrder'], headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print(res.status_code, res.content, res.headers)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()
        res = res.json()
        self.finalize = res['finalize']
        self.auths = res['authorizations']

    def fetchChallenge(self, type):
        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.auths[0]
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')
 
        data['payload'] = ''

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}
        res = requests.post(self.auths[0], headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print(res.status_code, res.content)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()
        res = res.json()
        for chal in res['challenges']:
            if type == chal['type']:
                self.chalUrl = chal['url']
                self.token = chal['token']
                break

    def pickChallenge(self):
        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.chalUrl
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')
 
        payload = {}
        data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}
        res = requests.post(self.chalUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        print(res.status_code, res.content)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()