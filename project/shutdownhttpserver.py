from flask import Flask
import os
import signal

def apper():
    app = Flask(__name__)

    @app.route('/shutdown')
    def index():
        os.kill(os.getpid(), signal.SIGTERM)

    return app

def startdown(host):
    app = apper()
    app.run(host=host, port=5003)