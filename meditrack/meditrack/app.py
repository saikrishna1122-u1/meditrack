import os
import bcrypt
import boto3
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from werkzeug.utils import secure_filename

# --- Flask Configuration ---
app = Flask(_name_)
app.config["SECRET_KEY"] = "d2c8f7a6e5b4c3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["ALLOWED_EXTENSIONS"] = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

# Create uploads folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- AWS Setup (Hardcoded Region & SNS Topic ARN) ---
AWS_REGION = "us-east-1"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:715841344567:meditrack"

# DynamoDB Table Names
USERS_TABLE = "meditrack_users"
MEDICINES_TABLE = "meditrack_medicines"
DOCUMENTS_TABLE = "meditrack_documents"

# AWS Resources
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)

users_table = dynamodb.Table(USERS_TABLE)
medicines_table = dynamodb.Table(MEDICINES_TABLE)
documents_table = dynamodb.Table(DOCUMENTS_TABLE)

# --- Utility Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_email():
    return session.get('email')

def get_user_fullname():
    return session.get('full_name')

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
    if get_user_email():
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        response = users_table.get_item(Key={'email': email})
        user = response.get('Item')

        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            session['email'] = email
            session['full_name'] = user.get('full_name', '')
            users_table.update_item(
                Key={'email': email},
                UpdateExpression="SET last_login = :val1",
                ExpressionAttributeValues={':val1': datetime.utcnow().isoformat()}
            )
            return redirect(url_for('home'))

        flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
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

        # Check if user exists
        if 'Item' in users_table.get_item(Key={'email': email}):
            flash("User already exists", "danger")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_data = {
            "email": email,
            "full_name": full_name,
            "password": hashed_pw,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }

        users_table.put_item(Item=user_data)
        flash("Registration successful", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/home')
def home():
    if not get_user_email():
        return redirect(url_for('login'))

    email = get_user_email()
    med_count = medicines_table.scan(
        FilterExpression="user_email = :e", 
        ExpressionAttributeValues={":e": email}
    )['Count']

    doc_count = documents_table.scan(
        FilterExpression="user_email = :e", 
        ExpressionAttributeValues={":e": email}
    )['Count']

    return render_template('home.html', med_count=med_count, doc_count=doc_count, full_name=get_user_fullname())

@app.route('/add_medicine', methods=['GET', 'POST'])
def add_medicine():
    if not get_user_email():
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
            "id": str(uuid.uuid4()),
            "user_email": get_user_email(),
            "name": name,
            "dosage": dosage,
            "frequency": freq,
            "notes": notes,
            "added_at": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat()
        }

        medicines_table.put_item(Item=medicine)
        notify_sns("New Medicine Added", f"{name} added by {get_user_email()}")
        flash("Medicine added", "success")
        return redirect(url_for('view_medicines'))

    return render_template('add_medicine.html')

@app.route('/view_medicines')
def view_medicines():
    if not get_user_email():
        return redirect(url_for('login'))

    email = get_user_email()
    response = medicines_table.scan(FilterExpression="user_email = :e", ExpressionAttributeValues={":e": email})
    medicines = sorted(response.get('Items', []), key=lambda x: x['added_at'], reverse=True)

    return render_template('view_medicines.html', medicines=medicines)

@app.route('/add_document', methods=['GET', 'POST'])
def add_document():
    if not get_user_email():
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            flash("Invalid file", "danger")
            return redirect(url_for('add_document'))

        filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        document = {
            "id": str(uuid.uuid4()),
            "user_email": get_user_email(),
            "name": request.form.get('name') or filename,
            "filename": filename,
            "path": filepath,
            "file_type": filename.rsplit('.', 1)[1].lower(),
            "uploaded_at": datetime.utcnow().isoformat(),
            "size": os.path.getsize(filepath)
        }

        documents_table.put_item(Item=document)
        notify_sns("New Document Uploaded", f"{filename} uploaded by {get_user_email()}")
        flash("Document uploaded", "success")
        return redirect(url_for('view_documents'))

    return render_template('add_document.html')

@app.route('/view_documents')
def view_documents():
    if not get_user_email():
        return redirect(url_for('login'))

    email = get_user_email()
    response = documents_table.scan(FilterExpression="user_email = :e", ExpressionAttributeValues={":e": email})
    documents = sorted(response.get('Items', []), key=lambda x: x['uploaded_at'], reverse=True)

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

if _name_ == '_main_':
    app.run(debug=True, host='0.0.0.0', port=5000)
