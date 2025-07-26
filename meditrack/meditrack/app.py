import os
import certifi
import bcrypt
import boto3
import uuid
from datetime import datetime
from bson.objectid import ObjectId
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
import sys
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)

# --- Flask Configuration ---
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["ALLOWED_EXTENSIONS"] = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

# Create uploads folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- MongoDB Setup ---
try:
    client = MongoClient(app.config["MONGO_URI"], tls=True, tlsCAFile=certifi.where())
    client.admin.command("ping")
    db = client.get_default_database()
    print("✅ Successfully connected to MongoDB")
except Exception as e:
    print("❌ Could not connect to MongoDB")
    print(f"Error: {str(e)}")
    db = None
    sys.exit(1)

# --- AWS Setup ---
AWS_REGION = os.getenv("AWS_REGION") or "us-east-1"
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")  # e.g., "arn:aws:sns:us-east-1:xxxxx:meditrack_topic"

# DynamoDB Table Names
USERS_TABLE = "meditrack_users"
MEDICINES_TABLE = "meditrack_medicines"
DOCUMENTS_TABLE = "meditrack_documents"

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE)
medicines_table = dynamodb.Table(MEDICINES_TABLE)
documents_table = dynamodb.Table(DOCUMENTS_TABLE)

# --- Utilities ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_email():
    return session.get('email')

def get_user_fullname():
    return session.get('full_name')

def sync_to_dynamodb(table, data):
    try:
        table.put_item(Item=data)
    except Exception as e:
        print(f"[DynamoDB Sync Error] {e}")

def notify_sns(subject, message):
    try:
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except Exception as e:
        print(f"[SNS Error] {e}")

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login')) if not get_user_email() else redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not db:
        return "Database connection error", 500
    if get_user_email():
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = db.users.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode(), user['password']):
            session['email'] = email
            session['full_name'] = user.get('full_name', '')
            db.users.update_one({'email': email}, {'$set': {'last_login': datetime.utcnow()}})
            return redirect(url_for('home'))

        flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not db:
        return "Database error", 500
    if get_user_email():
        return redirect(url_for('home'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if not full_name or not email or not password or password != confirm:
            flash("Check all fields and confirm password", "danger")
            return redirect(url_for('register'))

        if db.users.find_one({'email': email}):
            flash("User already exists", "danger")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        user_data = {
            "_id": str(uuid.uuid4()),
            "full_name": full_name,
            "email": email,
            "password": hashed_pw,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }

        db.users.insert_one(user_data)
        sync_to_dynamodb(users_table, {**user_data, "password": user_data["password"].decode()})
        flash("Registration successful", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/home')
def home():
    if not db or not get_user_email():
        return redirect(url_for('login'))

    med_count = db.medicines.count_documents({'user_email': get_user_email()})
    doc_count = db.documents.count_documents({'user_email': get_user_email()})
    return render_template('home.html', med_count=med_count, doc_count=doc_count, full_name=get_user_fullname())

@app.route('/add_medicine', methods=['GET', 'POST'])
def add_medicine():
    if not db or not get_user_email():
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        dosage = request.form.get('dosage')
        freq = request.form.get('frequency')
        notes = request.form.get('notes', '')

        if not name or not dosage:
            flash("Name and dosage required", "danger")
            return redirect(url_for('add_medicine'))

        medicine = {
            "_id": str(uuid.uuid4()),
            "user_email": get_user_email(),
            "name": name,
            "dosage": dosage,
            "frequency": freq,
            "notes": notes,
            "added_at": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat()
        }

        db.medicines.insert_one(medicine)
        sync_to_dynamodb(medicines_table, medicine)
        notify_sns("New Medicine Added", f"{name} added by {get_user_email()}")
        flash("Medicine added", "success")
        return redirect(url_for('view_medicines'))

    return render_template('add_medicine.html')

@app.route('/view_medicines')
def view_medicines():
    if not db or not get_user_email():
        return redirect(url_for('login'))

    medicines = list(db.medicines.find({'user_email': get_user_email()}).sort('added_at', -1))
    return render_template('view_medicines.html', medicines=medicines)

@app.route('/add_document', methods=['GET', 'POST'])
def add_document():
    if not db or not get_user_email():
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            flash("Invalid file", "danger")
            return redirect(url_for('add_document'))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        document = {
            "_id": str(uuid.uuid4()),
            "user_email": get_user_email(),
            "name": request.form.get('name') or filename,
            "filename": filename,
            "path": filepath,
            "file_type": filename.rsplit('.', 1)[1].lower(),
            "uploaded_at": datetime.utcnow().isoformat(),
            "size": os.path.getsize(filepath)
        }

        db.documents.insert_one(document)
        sync_to_dynamodb(documents_table, document)
        notify_sns("New Document Uploaded", f"{filename} uploaded by {get_user_email()}")
        flash("Document uploaded", "success")
        return redirect(url_for('view_documents'))

    return render_template('add_document.html')

@app.route('/view_documents')
def view_documents():
    if not db or not get_user_email():
        return redirect(url_for('login'))

    documents = list(db.documents.find({'user_email': get_user_email()}).sort('uploaded_at', -1))
    return render_template('view_documents.html', documents=documents)

@app.route('/download/<filename>')
def download(filename):
    if not get_user_email():
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>Page not found</p>", 404

@app.errorhandler(500)
def server_error(e):
    return "<h1>500</h1><p>Internal server error</p>", 500

if __name__ == '__main__':
    app.run(debug=True)
