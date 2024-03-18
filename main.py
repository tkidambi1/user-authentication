from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), unique=True, nullable=False)
  password = db.Column(db.String(60), nullable=False)


# Ensure that you are inside the app context before calling create_all()
with app.app_context():
  db.create_all()

  # Check if the test user already exists
  test_user = User.query.filter_by(username='testuser').first()

  # Create the test user if it doesn't exist
  if not test_user:
    hashed_password = bcrypt.generate_password_hash('testpassword').decode(
        'utf-8')
    new_test_user = User(username='testuser', password=hashed_password)
    db.session.add(new_test_user)
    db.session.commit()


# Default route redirects to login
@app.route('/')
def default():
  return redirect(url_for('login'))


# Flask route for handling user login
@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
      flash('Login successful!', 'success')
      return redirect(url_for('welcome'))
    else:
      flash('Login unsuccessful. Please check your username and password.',
            'danger')

  return render_template('login.html')


# Welcome route
@app.route('/welcome')
def welcome():
  return render_template('welcome_page.html')


# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
  if request.method == 'POST':
    # Your signup logic here
    fullname = request.form.get('fullname')
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if password != confirm_password:
      flash('Passwords do not match. Please try again.', 'danger')
    else:
      hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

      new_user = User(username=username, password=hashed_password)
      db.session.add(new_user)
      db.session.commit()

      flash('Your account has been created! You can now log in.', 'success')
      return redirect(url_for('login'))

  return render_template('signup.html')


# Logout route
@app.route('/logout')
def logout():
  # Perform logout operations if needed
  flash('You have been logged out.', 'success')
  return redirect(url_for('login'))


if __name__ == '__main__':
  app.run(debug=True)
