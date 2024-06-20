from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os
import cv2
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check your email and password', 'danger')
    return render_template('login.html')

@app.route('/logout',methods=['POST'])
@login_required
def logout():
    logout_user()
    flash("You have been succesfully logout",'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='email-confirm')
            return redirect(url_for('reset_password', token=token))
        else:
            flash('Email does not exist', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user = User.query.filter_by(email=email).first()
        user.password = hashed_password
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/upload_video', methods=['POST'])
@login_required
def upload_video():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
    
    if file:
        # Ensure 'uploads' directory exists
        upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        filename = os.path.join(upload_dir, file.filename)
        file.save(filename)
        session['uploaded_video'] = filename
        flash('Video uploaded successfully', 'success')
        return redirect(url_for('convert_video'))
    
    flash('Failed to upload video', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/convert_video', methods=['GET', 'POST'])
@login_required
def convert_video():
    if request.method == 'POST':
        format = request.form.get('format')
        uploaded_video = session.get('uploaded_video')

        if uploaded_video and format:
            try:
                # Read the uploaded video using OpenCV
                video_capture = cv2.VideoCapture(uploaded_video)

                # Get the codec for the specified format
                if format == 'mp4':
                    codec = cv2.VideoWriter_fourcc(*'mp4v')
                    extension = '.mp4'
                elif format == 'avi':
                    codec = cv2.VideoWriter_fourcc(*'XVID')
                    extension = '.avi'
                elif format == 'mov':
                    codec = cv2.VideoWriter_fourcc(*'mp4v')
                    extension = '.mov'
                else:
                    flash('Unsupported format', 'danger')
                    return redirect(url_for('dashboard'))

                output_filename = f'converted{extension}'
                output_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], output_filename)

                # Get frame width, height, and fps
                frame_width = int(video_capture.get(cv2.CAP_PROP_FRAME_WIDTH))
                frame_height = int(video_capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
                fps = video_capture.get(cv2.CAP_PROP_FPS)

                # Create a VideoWriter object
                out = cv2.VideoWriter(output_path, codec, fps, (frame_width, frame_height))

                while True:
                    ret, frame = video_capture.read()
                    if not ret:
                        break
                    out.write(frame)

                video_capture.release()
                out.release()

                return send_file(BytesIO(open(output_path, 'rb').read()), as_attachment=True, download_name=output_filename)

            except Exception as e:
                error_message = f'Failed to convert video: {str(e)}'
                app.logger.error(error_message)
                flash(error_message, 'danger')
                return redirect(url_for('dashboard'))

        flash('No video to convert or format not specified', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('convert_video.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
