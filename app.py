import datetime
import jwt

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import TIMESTAMP, func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://flask_user:flask_pass@localhost/flask_project_db_test'
db = SQLAlchemy(app)

app.config["SECRET_KEY"] = "abcdefghijklmnopqrstuvwxyz"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=True)

    def __int__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return f"<User {self.username}"


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    rate = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created = db.Column(TIMESTAMP, server_default=func.now())
    updated = db.Column(TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            current_user = User.query.filter_by(email=data['email']).first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify", 401, {"message":"Login required"})

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response("Could not verify", 401, {"message": "User not found"})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'email': user.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=10)
        }, app.config['SECRET_KEY'], "HS256")
        return make_response(jsonify({'token': token}), 201)

    return make_response("Could not verify", 401, {"message": "Login required"})


@app.route("/users", methods=["GET"])
@token_required
def get_all_users(current_user):
    output = []
    users = User.query.all()
    for user in users:
        user_data = {}
        user_data['username'] = user.username
        user_data['email'] = user.email
        output.append(user_data)
    return jsonify({"message": output})


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    password = data['password']
    username = data['username']
    email = data['email']
    first_name = data['first_name']
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(id=2,
                    username=username,
                    email=email,
                    password=hashed_password,
                    first_name=first_name
                    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "New User Created"})


@app.route('/job/create', methods=['POST'])
@token_required
def create_job(current_user):
    data = request.get_json()

    job = Job(user_id=current_user.id,
              title=data['title'],
              latitude=data['latitude'],
              longitude=data['longitude'],
              is_active=True)
    db.session.add(job)
    db.session.commit()
    return jsonify({'message': 'new job created'})


@app.route('/job/<id>', methods=['PUT'])
@token_required
def update_job(current_user, id):
    data = request.get_json()
    job = Job.query.filter_by(id=id)
    if not job.first():
        return jsonify({'message': 'no job found'})

    job = job.filter_by(is_active=True)
    if not job.first():
        return jsonify({'message': 'job has been deleted'})
    job = job.first()
    job.title = data['title'],
    job.latitude = data['latitude'],
    job.longitude = data['longitude'],
    db.session.commit()
    return jsonify({'message': 'Job updated successfully'})


@app.route('/job/delete/<id>', methods=['DELETE'])
@token_required
def delete_job(current_user, id):
    job = Job.query.filter_by(id=id)
    if not job.first():
        return jsonify({'message': 'no job found'})

    job = job.filter_by(is_active=True)
    if not job.first():
        return jsonify({'message': 'job has been already deleted'})

    job = job.first()
    job.is_active = False
    db.session.commit()
    return jsonify({'message': 'Job deleted successfully'})


@app.route('/job/all', methods=['GET'])
@token_required
def get_jobs(current_user):
    jobs = Job.query.filter_by(user_id=current_user.id, is_active=True).all()
    output = []
    for job in jobs:
        book_data = {}
        book_data['id'] = job.id
        book_data['user_id'] = job.user_id
        book_data['title'] = job.title
        book_data['latitude'] = job.latitude
        book_data['longitude'] = job.longitude
        book_data['is_active'] = job.is_active
        book_data['created'] = job.created
        book_data['updated'] = job.updated
        output.append(book_data)

    return jsonify({'list_of_jobs': output})


if __name__ == "__main__":
    app.run()
