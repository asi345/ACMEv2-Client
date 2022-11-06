from tkinter import W
from tracemalloc import start
import requests
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from binascii import unhexlify
from hashlib import sha256
import threading
from time import sleep
import os

from chalhttpserver import starthttp
from dnsserver import DNSserver
from certhttpserver import startcert
from shutdownhttpserver import startdown

class ACMEClient(object):

    def __init__(self, dir) -> None:
        self.dir = dir
        self.urls = {}
        self.nonce = None
        self.privateKey = None
        self.publicKey = None
        self.accountUrl = None
        self.orderUrl = None
        self.finalize = None
        self.auths = []
        self.chalUrls = []
        self.domainUrls = {}
        self.tokens = {}
        self.thumbprint = None
        self.keyAuths = {}
        self.certPrivKey = None
        self.certPubKey = None
        self.csr = None
        self.certUrl = None
        self.certificate = None
        self.httpthread = None
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
        self.certPrivKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        with open('key.pem', 'wb') as writer:
            writer.write(self.certPrivKey.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    def getPublicKey(self):
        self.publicKey = self.privateKey.public_key().public_numbers()
        self.certPubKey = self.certPrivKey.public_key().public_numbers()

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

        dic = dict(protected['jwk'])
        self.thumbprint = json.dumps(dic, sort_keys=True, separators=(",", ":"))
        
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
        #print('order', res.status_code, res.content, res.headers)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()
        self.orderUrl = res.headers['Location']
        res = res.json()
        self.finalize = res['finalize']
        self.auths = res['authorizations']

    def fetchChallenge(self, typ):
        for auth in self.auths:
            data = {'protected':None, 'payload':None, 'signature':None}

            protected = {}
            protected['alg'] = 'RS256'
            protected['kid'] = self.accountUrl
            protected['nonce'] = self.nonce
            protected['url'] = auth
            data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')
    
            data['payload'] = ''

            headpay = f"{data['protected']}.{data['payload']}"
            signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            headers = {'Content-type': 'application/jose+json'}
            res = requests.post(auth, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
            #print(type(res), res.status_code, res.content)
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            else:
                self.nonce = self.getNonce()
            res = res.json()
            for chal in res['challenges']:
                if typ == chal['type']:
                    self.chalUrls.append(chal['url'])
                    self.domainUrls[chal['url']] = res['identifier']['value']
                    self.tokens[chal['url']] = chal['token']
                    hasher = sha256(self.thumbprint.encode('utf-8')).digest()
                    self.keyAuths[chal['token']] = f"{chal['token']}.{base64.urlsafe_b64encode(hasher).rstrip(b'=').decode('utf-8')}"
                    break

    def pickChallenges(self):
        for chalUrl in self.chalUrls:
            data = {'protected':None, 'payload':None, 'signature':None}

            protected = {}
            protected['alg'] = 'RS256'
            protected['kid'] = self.accountUrl
            protected['nonce'] = self.nonce
            protected['url'] = chalUrl
            data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')
    
            payload = {}
            data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

            headpay = f"{data['protected']}.{data['payload']}"
            signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            headers = {'Content-type': 'application/jose+json'}
            res = requests.post(chalUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
            #print(res.status_code, res.content)
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            else:
                self.nonce = self.getNonce()

    def pollChallenge(self, chalUrl):
        for i in range(5):
            data = {'protected':None, 'payload':None, 'signature':None}

            protected = {}
            protected['alg'] = 'RS256'
            protected['kid'] = self.accountUrl
            protected['nonce'] = self.nonce
            protected['url'] = chalUrl
            data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

            data['payload'] = ''

            headpay = f"{data['protected']}.{data['payload']}"
            signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            headers = {'Content-type': 'application/jose+json'}
            res = requests.post(chalUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            else:
                self.nonce = self.getNonce()
            
            res = res.json()
            if res['status'] == 'valid':
                return
            sleep(2)

    def pollOrder(self, state):
        for i in range(5):
            data = {'protected':None, 'payload':None, 'signature':None}

            protected = {}
            protected['alg'] = 'RS256'
            protected['kid'] = self.accountUrl
            protected['nonce'] = self.nonce
            protected['url'] = self.orderUrl
            data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

            data['payload'] = ''

            headpay = f"{data['protected']}.{data['payload']}"
            signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            headers = {'Content-type': 'application/jose+json'}
            res = requests.post(self.orderUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
            #print(res.status_code, res.content)
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            else:
                self.nonce = self.getNonce()
            
            res = res.json()
            if res['status'] == state:
                return res
            sleep(2)      

    def chalhttp(self, domains, record):
        zone = '\n'.join([f"{domain}. 60 A {record}" for domain in domains])
        dns = DNSserver(zone)
        dns.start()

        self.httpthread = threading.Thread(target=starthttp, args=('0.0.0.0', self.keyAuths))
        self.httpthread.start()

        self.pickChallenges()
        for chalUrl in self.chalUrls:
            self.pollChallenge(chalUrl)

        self.pollOrder('ready')

    def chaldns(self):
        dns = DNSserver(zone='')
        dns.start()

        keyAuths = [self.keyAuths[self.tokens[chalUrl]] for chalUrl in self.chalUrls]
        b64keyAuths = [base64.urlsafe_b64encode(sha256(keyAuth.encode('utf-8')).digest()).rstrip(b"=").decode('utf-8')
            for keyAuth in keyAuths]
        zone = '\n'.join([f'_acme-challenge.{self.domainUrls[chalUrl]}. 300 IN TXT "{b64keyAuth}"' for b64keyAuth, chalUrl in zip(b64keyAuths, self.chalUrls)])
        dns.setZone(zone)
        for chalUrl in self.chalUrls:
            #keyAuth = self.keyAuths[self.tokens[chalUrl]]
            #b64keyAuth = base64.urlsafe_b64encode(sha256(keyAuth.encode('utf-8')).digest()).rstrip(b"=").decode('utf-8')
            #zone = f'_acme-challenge.{self.domainUrls[chalUrl]}. 300 IN TXT "{b64keyAuth}"'
            #dns.setZone(zone)

            data = {'protected':None, 'payload':None, 'signature':None}

            protected = {}
            protected['alg'] = 'RS256'
            protected['kid'] = self.accountUrl
            protected['nonce'] = self.nonce
            protected['url'] = chalUrl
            data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

            payload = {}
            data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

            headpay = f"{data['protected']}.{data['payload']}"
            signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            headers = {'Content-type': 'application/jose+json'}
            res = requests.post(chalUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
            print('dns', res.status_code, res.content)
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            else:
                self.nonce = self.getNonce()

            self.pollChallenge(chalUrl)

        self.pollOrder('ready')

    def createCsr(self, domains):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'TR'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Istanbul'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Atasehir'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Dumankaya Ikon'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'A1-353'),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False
        ).sign(self.certPrivKey, hashes.SHA256())
        csr = csr.public_bytes(serialization.Encoding.DER)
        self.csr = base64.urlsafe_b64encode(csr).rstrip(b"=").decode('utf-8')

    def finishIt(self):
        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.finalize
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

        payload = {}
        payload['csr'] = self.csr
        data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}
        res = requests.post(self.finalize, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print(res.status_code, res.content, res.headers)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()

    def getCert(self):
        self.certUrl = self.pollOrder('valid')['certificate']

        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.certUrl
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

        data['payload'] = ''

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}
        res = requests.post(self.certUrl, headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print('cert', res.content, res.headers)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()

        self.certificate = res.content
        with open('cert.pem', 'wb') as writer:
            writer.write(self.certificate)

    def setupHttpServers(self):
        certthread = threading.Thread(target=startcert, args=('0.0.0.0', os.path.realpath('cert.pem'), os.path.realpath('key.pem')))
        certthread.start()

        stopthread = threading.Thread(target=startdown, args=['0.0.0.0'])
        stopthread.start()

    def revoke(self):
        data = {'protected':None, 'payload':None, 'signature':None}

        protected = {}
        protected['alg'] = 'RS256'
        protected['kid'] = self.accountUrl
        protected['nonce'] = self.nonce
        protected['url'] = self.urls['revokeCert']
        data['protected'] = base64.urlsafe_b64encode(json.dumps(protected).encode('utf-8')).rstrip(b"=").decode('utf-8')

        payload = {}
        certPem = x509.load_pem_x509_certificate(self.certificate)
        payload['certificate'] = base64.urlsafe_b64encode(certPem.public_bytes(encoding=serialization.Encoding.DER)
            ).rstrip(b"=").decode('utf-8')
        data['payload'] = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).rstrip(b"=").decode('utf-8')

        headpay = f"{data['protected']}.{data['payload']}"
        signature = self.privateKey.sign(headpay.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        data['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

        headers = {'Content-type': 'application/jose+json'}
        res = requests.post(self.urls['revokeCert'], headers=headers, data=json.dumps(data), verify='pebble.minica.pem')
        #print(res.status_code, res.content, res.headers)
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        else:
            self.nonce = self.getNonce()