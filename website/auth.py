from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password. Please try again.', category='err')
        else:
            flash('Email dosn\'t exist.', category='err')
            return redirect(url_for('views.home'))

    return render_template('login.html', boolean=True)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for(auth.login))

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('r already exist.', category='errpython main.py')
        elif len(email) < 4:
            flash('Email Address is too short. Must be atleast 4 characters long.', category='err')
        elif len(first_name )< 2:
            flash('Name is too short. Must be atleast 2 characters long.', category='err')
        elif password1 != password2:
            flash('Passwords dosn\'t match.', category='err')
        elif len(password1) < 7:
            flash('password is too short. Must be atleast 7 characters long.', category='err')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created Successfully!', category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html')