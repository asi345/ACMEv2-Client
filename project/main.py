import argparse

import client
from client import ACMEClient

parser = argparse.ArgumentParser()
parser.add_argument('type', type=str, choices=['dns01', 'http01'])
parser.add_argument('--dir', type=str, required=True, help='server directory url')
parser.add_argument('--record', type=str, required=True, help='IPv4 address to be returned for queries')
parser.add_argument('--domain', type=str, action='append', required=True, help='domains to obtain certificate')
parser.add_argument('--revoke', action='store_true', help='if the certificate will be removed or not')

args = parser.parse_args()
typ = args.type[:-2] + '-' + args.type[-2:]

client = ACMEClient(args.dir)
client.setupUrls()
client.getNonce()
client.createAccount()
client.submitOrder(args.domain)
client.fetchChallenge(typ)

if typ == 'http-01':
    client.chalhttp(args.domain, args.record)
else:
    client.chaldns()

client.createCsr(args.domain)
client.finishIt()
client.getCert()

client.setupHttpServers()