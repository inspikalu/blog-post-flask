from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os
from bson.objectid import ObjectId
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set the MongoDB URI from the environment variable
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

# Check if environment variables are loaded
print("MONGO_URI:", app.config["MONGO_URI"])
print("JWT_SECRET_KEY:", app.config["JWT_SECRET_KEY"])

if not app.config["MONGO_URI"]:
    raise ValueError("No MONGO_URI set for Flask application. Did you forget to set it in the .env file?")
if not app.config["JWT_SECRET_KEY"]:
    raise ValueError("No JWT_SECRET_KEY set for Flask application. Did you forget to set it in the .env file?")

# Initialize PyMongo, Bcrypt, and JWTManager
try:
    mongo = PyMongo(app)
    print("MongoDB connected:", mongo.db)
except Exception as e:
    print("Failed to connect to MongoDB:", e)
    raise

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/signup', methods=['POST'])
def signup():
    user_collection = mongo.db.users
    user_data = request.get_json()

    # Ensure only the required fields are processed
    required_fields = ['username', 'password', 'fullname', 'email']
    for field in required_fields:
        if field not in user_data:
            return jsonify({"message": f"Missing field: {field}"}), 400

    # Check if the email already exists
    existing_user = user_collection.find_one({"email": user_data["email"]})
    if existing_user:
        return jsonify({"message": "Email already exists"}), 409

    # Prepare user data for insertion
    new_user = {
        "username": user_data['username'],
        "password": bcrypt.generate_password_hash(user_data['password']).decode('utf-8'),
        "fullname": user_data['fullname'],
        "email": user_data['email']
    }

    # Insert the new user
    user_id = user_collection.insert_one(new_user).inserted_id
    return jsonify({"message": "User signed up", "user_id": str(user_id)}), 201

@app.route('/login', methods=['POST'])
def login():
    user_collection = mongo.db.users
    user_data = request.get_json()
    user = user_collection.find_one({"email": user_data["email"]})

    if user and bcrypt.check_password_hash(user["password"], user_data["password"]):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/blog_posts', methods=['POST'])
@jwt_required()
def add_blog_post():
    blog_post_collection = mongo.db.blog_posts
    post_data = request.get_json()
    post_data['author_id'] = ObjectId(get_jwt_identity())
    post_data['created_at'] = datetime.utcnow().isoformat()
    post_id = blog_post_collection.insert_one(post_data).inserted_id
    return jsonify({"message": "Blog post added", "post_id": str(post_id)}), 201

@app.route('/blog_posts', methods=['GET'])
def get_blog_posts():
    blog_post_collection = mongo.db.blog_posts
    blog_posts = list(blog_post_collection.find())
    for post in blog_posts:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])
    return jsonify(blog_posts), 200

@app.route('/blog_posts/<post_id>', methods=['GET'])
def get_blog_post(post_id):
    blog_post_collection = mongo.db.blog_posts
    post = blog_post_collection.find_one({"_id": ObjectId(post_id)})
    if post:
        post['_id'] = str(post['_id'])
        post['author_id'] = str(post['author_id'])
        return jsonify(post), 200
    else:
        return jsonify({"message": "Blog post not found"}), 404

@app.route('/blog_posts/<post_id>', methods=['PUT'])
@jwt_required()
def update_blog_post(post_id):
    blog_post_collection = mongo.db.blog_posts
    post_data = request.get_json()
    post = blog_post_collection.find_one({"_id": ObjectId(post_id)})

    if post and str(post['author_id']) == get_jwt_identity():
        blog_post_collection.update_one({"_id": ObjectId(post_id)}, {"$set": post_data})
        return jsonify({"message": "Blog post updated"}), 200
    else:
        return jsonify({"message": "Unauthorized or blog post not found"}), 401

@app.route('/blog_posts/<post_id>', methods=['DELETE'])
@jwt_required()
def delete_blog_post(post_id):
    blog_post_collection = mongo.db.blog_posts
    post = blog_post_collection.find_one({"_id": ObjectId(post_id)})

    if post and str(post['author_id']) == get_jwt_identity():
        blog_post_collection.delete_one({"_id": ObjectId(post_id)})
        return jsonify({"message": "Blog post deleted"}), 200
    else:
        return jsonify({"message": "Unauthorized or blog post not found"}), 401

if __name__ == '__main__':
    app.run(debug=True)
