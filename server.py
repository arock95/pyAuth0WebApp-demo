from functools import wraps
import json
from os import environ as env
from os.path import join, dirname
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask, jsonify, redirect, render_template, session, url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
app.secret_key = env.get("secret_key")

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=env.get("client_id"),
    client_secret=env.get("client_secret"),
    api_base_url='https://authrock.auth0.com',
    access_token_url='https://authrock.auth0.com/oauth/token',
    authorize_url='https://authrock.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email'
    },
)


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id':userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='http://localhost:5000/callback')


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': env.get("client_id")}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/')
def home():
    return render_template('home.html')