from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_migrate import Migrate
from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy.sql import func
import uuid as uuid
from werkzeug.utils import secure_filename
from flask_login import UserMixin
import json
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)


class Services(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  data = db.Column(db.String(10000))
  date = db.Column(db.DateTime(timezone=True), default=func.now())
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(150), unique=True)
  password = db.Column(db.String(150))
  first_name = db.Column(db.String(150))
  last_name = db.Column(db.String(150))
  dateofbirth = db.Column(db.DateTime)
  address = db.Column(db.String(300))
  Services = db.relationship('Services')
  profile_pic = profile_pic = db.Column(db.String(), nullable=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login1.html", user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('FName')
        last_name = request.form.get('LName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        phone_num = request.form.get('Phone_Number')
        address = request.form.get('address')
        dateofbirth = request.form.get('DOD')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash(
    'First name must be greater than 1 character.',
     category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
          # Check for profile pic
        elif request.files['profile_pic']:
           profile_pic = request.files['profile_pic']
			     # Grab Image Name
           pic_filename = secure_filename(profile_pic.filename)
			      # Set UUID
           pic_name = str(uuid.uuid1()) + "_" + pic_filename
			      # Save That Image
           saver = request.files['profile_pic']

			     # Change it to a string to save to db
           profile_pic = pic_name
    
           db.session.commit()
           saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha1', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("register.html", user=current_user)

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("index.html")


@app.route('/delete-service', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Services.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})






if __name__ == '__main__':
      app.run(debug=True)
