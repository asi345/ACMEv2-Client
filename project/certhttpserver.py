from flask import Flask

def apper():
    app = Flask(__name__)

    @app.route('/')
    def index():
        return 'ACME is too hard :('

    return app

def startcert(host, certFile, keyFile):
    app = apper()
    app.run(host, ssl_context=(certFile, keyFile), port=5001)