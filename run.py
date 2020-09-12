import json
import datetime

import bcrypt
import flask
import jwt
from flask import request, session, make_response, jsonify
from flask_login import LoginManager
from pymongo import MongoClient
from functools import wraps
from flask_cors import CORS

app = flask.Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = b'_@!#_#&Ty4%lvdA67lkl1g>'
CORS(app)


@app.route('/', methods=['GET'])
def home():
    return '''<h1>some bullshit</h1>
<p>more placeholder</p>'''


@app.route('/login', methods=['GET', 'POST', 'PUT'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    db_users = db.users
    login_user = db_users.find_one({'username': auth.username})
    if not login_user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if bcrypt.hashpw(auth.password.encode('utf-8'), login_user['password']) == \
            login_user['password']:
        return get_token(login_user['username'])

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm = "login required"'})


def get_token(username):
    token = jwt.encode({'user': username,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1440)},
                       app.secret_key)
    return jsonify({'token': token.decode('UTF-8')})


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        body = get_json_from_request()
        username_ = body['username']
        existing_user = db.users.find_one({'username': username_})
        if existing_user is None:
            hash_pass = bcrypt.hashpw(body['password'].encode('utf-8'), bcrypt.gensalt())
            db.users.insert_one({'username': username_, 'password': hash_pass})
            session['username'] = username_
            return get_token(username_)
        return jsonify({'message': 'User already exists!'}), 409
    return jsonify({'User Not Found'}), 404


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            decoded_body = jwt.decode(token.encode('utf-8'), app.secret_key)
            current_user = db.users.find_one({'username': decoded_body['user']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/cars', methods=['GET', 'POST'])
@token_required
def cars(current_user):
    if request.method == 'POST':
        body = get_json_from_request()
        username_ = current_user['username']
        carname_ = body['name']
        body['username'] = username_
        existing_car = db.cars.find_one({'username': username_, 'name': carname_})
        if existing_car is None:
            db.cars.insert_one(body)
            return True
        return jsonify({'message': 'Car already exists!'}), 409
    if request.method == 'GET':
        username_ = current_user['username']
        existing_car = list(db.cars.find({'username': username_}))
        if len(existing_car) == 0:
            return jsonify({'message': 'No cars for this user'}), 404
        return jsonify(existing_car)


def get_json_from_request():
    return json.loads(request.data.decode('utf-8'))


def get_token_from_request():
    return request.headers['x-access-token']


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


client = MongoClient('localhost', 27017)
db = client.db
login_manager = LoginManager()
login_manager.init_app(app)

app.run(debug=True)
