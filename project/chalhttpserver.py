from flask import Flask, Response
import json

def apper(tokens):
    app = Flask(__name__)

    dic = tokens

    @app.route('/.well-known/acme-challenge/<string:token>')
    def reply(token):
        res = Response(dic[token])
        res.headers['Content-Type'] = 'application/octet-stream'
        return res

    @app.route('/')
    def main():
        return json.dumps(dic)

    return app

def starthttp(host, tokens):
    app = apper(tokens)
    app.run(host, port=5002)