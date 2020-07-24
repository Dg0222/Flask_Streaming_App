from flask import Flask, render_template, Response
import cv2
import sys
import numpy
import gunicorn

from functools import wraps
import json
import app
import subprocess
import sys
import gunicorn
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

"""Python Flask WebApp Auth0 integration starts here
"""

app = Flask(__name__,)
app.secret_key = 'CNT'
app.debug = True


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id='93SzbwQpaBonWBJDSJKyzuZ95V7UA0un',
    client_secret='UPz7eSTujQ-QxFgIvD9BMAnV-9ss5cYEVG30tBMOhrGhiYTDxMZ4GokaaUwUV5dY',
    api_base_url='https://dev-qzmwwjxs.us.auth0.com',
    access_token_url='https://dev-qzmwwjxs.us.auth0.com/oauth/token',
    authorize_url='https://dev-qzmwwjxs.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


# /server.py

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='https://flask-streaming-app2.herokuapp.com/live')


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': '93SzbwQpaBonWBJDSJKyzuZ95V7UA0un'}
    return redirect('https://dev-qzmwwjxs.us.auth0.com/v2/logout')


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))


"""Python Flask WebApp Auth0 integration ends here
"""


""" Actual Python App for video """
@app.route('/live')
def index():
    return render_template('index2.html')

@app.route('/static')
def s():
    return render_template('index.html')



def get_frame():
    camera=cv2.VideoCapture(0) 

    while True:
        retval, im = camera.read()
        imgencode=cv2.imencode('.jpg',im)[1]
        stringData=imgencode.tostring()
        yield (b'--frame\r\n'
            b'Content-Type: text/plain\r\n\r\n'+stringData+b'\r\n')

    del(camera)

@app.route('/calc')
def calc():
     return Response(get_frame(),mimetype='multipart/x-mixed-replace; boundary=frame')



if __name__ == '__main__':
    print("Starting server at http://localhost:5000/")
    app.run(host='0.0.0.0', port=5000, threaded = True)
