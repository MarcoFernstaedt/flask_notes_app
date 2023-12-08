from flask import Blueprint, render_template, request, flash

auth= Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html', user='Marco')

@auth.route('/logout')
def logout():
    return '<p>Logout</p>'

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash('Email Address is too short. Must be atleast 4 characters long.', category='err')
        elif len(first_name )< 2:
            flash('Name is too short. Must be atleast 2 characters long.', category='err')
        elif password1 != password2:
            flash('Passwords dosn\'t match.', category='err')
        elif len(password1) < 7:
            flash('password is too short. Must be atleast 7 characters long.', category='err')
        else:
            flash('Account created Successfully!', category='success')

    return render_template('signup.html')