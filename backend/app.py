import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env

from flask import Flask, request, render_template, redirect, url_for, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_bcrypt import Bcrypt  # For password hashing
import uuid
from openai import OpenAI  # New import for the updated interface
import pdfkit  # Ensure pdfkit and wkhtmltopdf are installed

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lugoo.db'
app.config['SECRET_KEY'] = 'yoursecretkeyhere'  # Needed for session management

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Instantiate the OpenAI client with the API key from the environment
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
if not os.getenv('OPENAI_API_KEY'):
    raise ValueError("OPENAI_API_KEY not found in environment variables.")

# ✅ Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)  # Store hashed passwords
    unique_code = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=True)  # Field for conversation title
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    transcript = db.Column(db.Text, nullable=True)  # Integrated conversation transcript
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

# New route: Export PDF
@app.route('/export_pdf/<int:conversation_id>')
def export_pdf(conversation_id):
    chat = ChatHistory.query.get(conversation_id)
    if not chat:
        return "Conversation not found", 404
    # Create simple HTML for the PDF
    html = f"""
    <html>
      <head>
        <meta charset="utf-8">
        <title>Conversation {conversation_id}</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 20px; }}
          .user-message {{ color: #fff; background-color: #4a4a4a; padding: 10px; border-radius: 10px; margin-bottom: 10px; }}
          .bot-message {{ color: #000; background-color: #e0e0e0; padding: 10px; border-radius: 10px; margin-bottom: 10px; }}
        </style>
      </head>
      <body>
        {chat.transcript if chat.transcript else "No conversation available."}
      </body>
    </html>
    """
    pdf = pdfkit.from_string(html, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=conversation_{conversation_id}.pdf'
    return response

# ✅ Home Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/home')
def home_logged_in():
    if "user_id" not in session:
        return redirect(url_for('home'))
    return render_template('home_logged_in.html')

# ✅ About Page
@app.route('/about')
def about():
    if "user_id" in session:
        return render_template('about_logged_in.html')
    else:
        return render_template('about_guest.html')

# ✅ User Authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists. Please choose another.')
        if not username or not password:
            return render_template('register.html', error='Please enter a username and password.')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        session["unique_code"] = user.unique_code
        return redirect(url_for('chat_page', unique_code=user.unique_code))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid username or password.')
        session["user_id"] = user.id
        session["unique_code"] = user.unique_code
        return redirect(url_for('chat_page', unique_code=user.unique_code))

@app.route('/logout')
def logout():
    session.pop("user_id", None)
    session.pop("unique_code", None)
    session.pop("last_chat", None)  # Clear last active chat on logout
    return redirect(url_for('home'))

# ✅ OpenAI Chat Function (updated for new interface)
def get_openai_response(prompt):
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"

# ✅ Chat Functionality
@app.route('/chat/<unique_code>', methods=['GET', 'POST'])
def chat_page(unique_code):
    user = User.query.filter_by(unique_code=unique_code).first()
    if not user:
        return "Invalid user code.", 404

    history = ChatHistory.query.filter_by(user_id=user.id).order_by(ChatHistory.timestamp.desc()).all()

    if request.method == 'POST':
        prompt = request.form.get('prompt')
        if prompt:
            answer = get_openai_response(prompt)
            conv_id = request.args.get('conversation_id')
            if conv_id:
                # Update existing conversation by appending the new Q&A pair.
                chat = ChatHistory.query.get(conv_id)
                new_entry = f"<div class='user-message'>{prompt}</div>"
                new_entry += f"<div class='bot-message'><strong>Lugoo:</strong> {answer}</div>"
                chat.transcript = (chat.transcript or "") + new_entry
                db.session.commit()
            else:
                # Create a new conversation.
                transcript = f"<div class='user-message'>{prompt}</div>"
                transcript += f"<div class='bot-message'><strong>Lugoo:</strong> {answer}</div>"
                chat = ChatHistory(user_id=user.id, message=prompt, response=answer, transcript=transcript)
                db.session.add(chat)
                db.session.commit()
                if not chat.title:
                    chat.title = f"Conversation {chat.id}"
                    db.session.commit()
            # For AJAX requests, return JSON.
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
                return jsonify({'answer': answer})
            return redirect(url_for('chat_page', unique_code=user.unique_code, conversation_id=chat.id))
    else:
        conv_id = request.args.get('conversation_id')
        new_flag = request.args.get('new')
        if conv_id:
            # If a conversation is explicitly selected, save it as the last active chat.
            session["last_chat"] = conv_id
            active_chat = ChatHistory.query.get(conv_id)
        elif new_flag:
            active_chat = None
            session.pop("last_chat", None)
        elif "last_chat" in session:
            # No conversation specified in the URL but one was stored in the session.
            conv_id = session.get("last_chat")
            active_chat = ChatHistory.query.filter_by(id=conv_id, user_id=user.id).first()
            if not active_chat:
                active_chat = None
        else:
            active_chat = None

        return render_template('chat.html', user=user, history=history, active_chat=active_chat)

# ✅ Conversation Management Endpoints
@app.route('/rename_conversation/<int:conversation_id>', methods=['POST'])
def rename_conversation(conversation_id):
    new_title = request.form.get('new_title')
    chat = ChatHistory.query.get(conversation_id)
    if chat:
        chat.title = new_title
        db.session.commit()
        return "Renamed", 200
    return "Conversation not found", 404

@app.route('/delete_conversation/<int:conversation_id>', methods=['POST'])
def delete_conversation(conversation_id):
    chat = ChatHistory.query.get(conversation_id)
    if chat:
        db.session.delete(chat)
        db.session.commit()
        return "Deleted", 200
    return "Conversation not found", 404

# ✅ Profile Management
@app.route('/edit_user/<unique_code>', methods=['GET', 'POST'])
def edit_user(unique_code):
    user = User.query.filter_by(unique_code=unique_code).first()
    if not user:
        return "Invalid user code.", 404
    if request.method == 'POST':
        action = request.form.get("action")
        if action == "update_username":
            new_username = request.form.get('username')
            if not new_username:
                return render_template('edit_user.html', user=user, error='Please enter a username.')
            user.username = new_username
            db.session.commit()
        elif action == "change_password":
            new_password = request.form.get('new_password')
            if not new_password:
                return render_template('edit_user.html', user=user, error='Please enter a new password.')
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
        return redirect(url_for('edit_user', unique_code=user.unique_code))
    return render_template('edit_user.html', user=user)

# ✅ Delete User Route
@app.route('/delete_user/<unique_code>', methods=['POST'])
def delete_user(unique_code):
    user = User.query.filter_by(unique_code=unique_code).first()
    if not user:
        return "Invalid user code.", 404
    ChatHistory.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    session.pop("user_id", None)
    session.pop("unique_code", None)
    session.pop("last_chat", None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
