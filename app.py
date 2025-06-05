from datetime import datetime
from io import BytesIO

import qrcode
from flask import Flask, redirect, request, url_for, render_template, flash,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = '123456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique = True, nullable=False)
    password = db.Column(db.String(80),nullable=False)
    email = db.Column(db.String(80),nullable=False)

    Sessions = db.relationship('Session', backref='admin', lazy='dynamic')

    @property
    def is_active(self):
        return True  # or implement logic if you want to disable users

    @property
    def is_authenticated(self):
        return True  # usually True for logged-in users

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)  # return user ID as string

class Session(db.Model):
    __tablename__ = 'Session'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), unique = True, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(128), nullable=False)
    speaker = db.Column(db.String(80), nullable=False)
    summary = db.Column(db.String(128), nullable=True)

    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    feedbacks = db.relationship('Feedback', backref='session', lazy='dynamic')

class Attendee(db.Model):
    __tablename__ = 'attendee'
    id = db.Column(db.Integer, primary_key=True)
    device_hash = db.Column(db.String(80), unique = True, nullable=False)

    feedbacks = db.relationship('Feedback', backref='attendee', lazy='dynamic')

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(80), nullable=False)
    sentiment = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

    session_id = db.Column(db.Integer, db.ForeignKey('Session.id'), nullable=False)
    attendee_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=False)

class SentimentTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    feedback_id = db.Column(db.Integer, db.ForeignKey('feedback.id'), nullable=False)
    tag = db.Column(db.String(20))  # e.g., "positive", "negative", "neutral"


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

@app.route('/')
def index():  # put application's code here
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        confirm = request.form.get('confirm')

        if not username or not email or not password or not confirm:
            flash('All fields are required','danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match','danger')
            return redirect(url_for('register'))
        existing_user = Admin.query.filter_by(username=username).first()
        existing_email = Admin.query.filter_by(email=email).first()

        if existing_user:
            flash('Username already taken','danger')
            return redirect(url_for('register'))
        if existing_email:
            flash('Email already taken','danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_admin = Admin(username = username, email = email, password = hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin successfully created','success')
        return redirect(url_for('login'))
    return render_template('register.html')
@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Admin.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password','danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful','info')
    return redirect(url_for('login'))
@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    sessions = Session.query.filter_by(admin_id=current_user.id).all()
    return render_template('dashboard.html',sessions=sessions)

@app.route('/create_session',methods=['GET','POST'])
@login_required
def create_session():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        speaker = request.form.get('speaker')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        try:
            start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid start time','danger')
            return redirect(url_for('create_session'))
        if start_time > end_time:
            flash('Invalid end time','danger')
            return redirect(url_for('create_session'))
        new_session = Session(
            title = title,
            description = description,
            speaker = speaker,
            start_time = start_time,
            end_time = end_time,
            admin_id = current_user.id
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Session successfully created','success')
        return redirect(url_for('dashboard'))
    return render_template('create_session.html')

@app.route('/generate_summary/<int:session_id>',methods=['GET','POST'])
@login_required
def generate_summary(session_id):
    session = Session.query.get_or_404(session_id)

    if session.admin_id != current_user.id:
        flash('You do not have permission to see this session','danger')
        return redirect(url_for('dashboard'))
    feedbacks = session.feedbacks.all()
    if not feedbacks:
        flash('No feedbacks found','danger')
        return redirect(url_for('dashboard'))
    avg_rating = sum(f.rating for f in feedbacks) / len(feedbacks)
    summary = f"Average rating: {avg_rating:.1f}/5. Feedbacks Count: {len(feedbacks)}"
    summary +="Overall sentiment:"
    if avg_rating > 4:
        summary+="Positive"
    elif avg_rating >=2.5:
        summary+="Mixed"
    else:
        summary+="Negative"

    session.summary = summary
    db.session.commit()
    flash('Summary successfully generated','success')
    return redirect(url_for('dashboard'))

@app.route('/create_feedback/<int:session_id>',methods=['GET','POST'])
@login_required
def create_feedback(session_id):
    session = Session.query.get_or_404(session_id)

    if session.admin_id != current_user.id:
        flash('You do not have permission to see this session','danger')
        return redirect(url_for('dashboard'))
    feedbacks = Feedback.query.filter_by(session_id=session_id).all()
    return render_template('view_feedback.html',session=session,feedbacks=feedbacks)

@app.route('/create_QRcode/<int:session_id>',methods=['GET','POST'])
@login_required
def create_QRcode(session_id):
    feedback_url = url_for('submit_feedback',session_id=session_id,_external=True)
    qr = qrcode.make(feedback_url)
    img_io = BytesIO()
    qr.save(img_io)
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png',as_attachment=False,download_name='QRcode.png')

@app.route('/submit_feedback/<int:session_id>',methods=['GET','POST'])
def submit_feedback(session_id):
    session = Session.query.get_or_404(session_id)

    if request.method == 'POST':
        device_hash = request.remote_addr
        rating = int(request.form.get('rating'))
        comment = request.form.get('comment')
        sentiment = "Positive" if rating >= 3 else "Negative"

        attendee = Attendee.query.filter_by(device_hash=device_hash).first()
        if not attendee:
            attendee = Attendee(device_hash=device_hash)
            db.session.add(attendee)
            db.session.commit()

        feedback = Feedback(
            rating = rating,
            comment = comment,
            sentiment = sentiment,
            timestamp = datetime.utcnow(),
            session_id = session_id,
            attendee_id = attendee.id
        )
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback successfully submitted','success')
        return redirect(url_for('submit_feedback', session_id=session_id))
    return render_template('submit_feedback.html')
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
