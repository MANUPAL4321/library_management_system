from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'student_login'
login_manager.login_message_category = 'info'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"User('{self.email}', '{self.is_admin}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, is_admin=False).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('student_dashboard'))
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')
    return render_template('student_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('admin_register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin_register.html')

@app.route('/student_register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('student_register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Redirecting to your dashboard...', 'success')
        login_user(new_user)
        return redirect(url_for('student_login'))
    return render_template('student_register.html')

@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Dummy data for illustration; replace with actual queries
    issued_books = [
        {'title': 'Book 1', 'author': 'Author 1'},
        {'title': 'Book 2', 'author': 'Author 2'}
    ]
    new_issued_books = [
        {'title': 'New Book 1', 'author': 'New Author 1'}
    ]
    not_returned_books = [
        {'title': 'Not Returned Book 1', 'author': 'Not Returned Author 1'}
    ]
    
    return render_template('student_dashboard.html', 
                           issued_books=issued_books, 
                           new_issued_books=new_issued_books, 
                           not_returned_books=not_returned_books)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        user = User.query.get(current_user.id)

        if bcrypt.check_password_hash(user.password, current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('my_profile'))
        else:
            flash('Current password is incorrect', 'danger')

    return render_template('change_password.html')


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    return render_template('admin_dashboard.html')

@app.route('/my_profile', methods=['GET', 'POST'])
@login_required
def my_profile():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form.get('password')
        if email and email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash('Email is already taken by another user', 'danger')
                return redirect(url_for('my_profile'))
            current_user.email = email
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('my_profile'))
    return render_template('my_profile.html', email=current_user.email)

@app.route('/view_profile')
@login_required
def view_profile():
    return render_template('view_profile.html', email=current_user.email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/manage_books')
@login_required
def manage_books():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    # Logic to display and manage books
    return render_template('manage_books.html')

@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    if request.method == 'POST':
        # Logic to add a new book
        pass
    return render_template('add_book.html')

@app.route('/issue_book', methods=['GET', 'POST'])
@login_required
def issue_book():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    if request.method == 'POST':
        # Logic to issue a book
        pass
    return render_template('issue_book.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
