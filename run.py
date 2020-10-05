import json
import datetime

import bcrypt
import flask
import jwt
from bson import ObjectId
from bson.json_util import loads, dumps
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


@app.route('/checkToken', methods=['POST'])
def check_token():
    token = get_token_from_request()
    try:
        decoded_body = jwt.decode(token.encode('utf-8'), app.secret_key)
        current_user = db.users.find_one({'username': decoded_body['user']})
        if current_user:
            return jsonify({'message': 'Token is valid!'}), 200
        else:
            return jsonify({'message': 'Token that belong to user no longer exists!'}), 404
    except:
        return jsonify({'message': 'Token is invalid!'}), 401


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


@app.route('/cars', methods=['GET', 'POST', 'DELETE'])
@token_required
def cars(current_user):
    username = current_user['username']
    if request.method == 'POST':
        body = get_json_from_request()
        carname_ = body['name']
        body['username'] = username
        existing_car = db.cars.find_one({'username': username, 'name': carname_})
        if existing_car is None:
            db.cars.insert_one(body)
            return jsonify({'message': 'Car added'}), 200
        return jsonify({'message': 'Car already exists!'}), 409
    if request.method == 'GET':
        existing_car = list(db.cars.find({'username': username}))
        if len(existing_car) == 0:
            return jsonify({'message': 'No cars for this user'}), 404
        return jsonify({'cars': dumps(existing_car)})
    if request.method == 'DELETE':
        body = get_json_from_request()
        car_id = ObjectId(body['$oid'])
        query_delete = {'username': username, '_id': car_id}
        existing_car = db.cars.find_one(query_delete)
        if existing_car is None:
            return jsonify({'message': 'No car found for id' + ' for this user'}), 404
        db.cars.delete_one(query_delete)
        return jsonify({'cars': dumps(existing_car)})


@app.route('/trips', methods=['GET', 'POST', 'DELETE'])
@token_required
def trips(current_user):
    username = current_user['username']
    if request.method == 'POST':
        body = get_json_from_request()
        body['username'] = username
        db.trips.insert_one(body)
        return jsonify({'message': 'Car added'}), 200
    if request.method == 'GET':
        existing_trips = list(db.trips.find({'username': username}))
        if len(existing_trips) == 0:
            return jsonify({'message': 'No trips for this user'}), 404
        return jsonify({'trips': dumps(existing_trips)})
    if request.method == 'DELETE':
        body = get_json_from_request()
        trip_id = ObjectId(body['$oid'])
        query_delete = {'username': username, '_id': trip_id}
        existing_trip = db.trips.find_one(query_delete)
        if existing_trip is None:
            return jsonify({'message': 'No car found for id' + ' for this user'}), 404
        db.cars.delete_one(query_delete)
        return jsonify({'trips': dumps(existing_trip)})


def get_json_from_request():
    return json.loads(request.data.decode('utf-8'))


def get_token_from_request() -> object:
    return request.headers['x-access-token']


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


client = MongoClient('localhost', 27017)
db = client.db
login_manager = LoginManager()
login_manager.init_app(app)

app.run(debug=True)
