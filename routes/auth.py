from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from models import User

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(
            username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            flash(f'مرحباً {user.username} 👋', 'success')
            return redirect(url_for('vulnerabilities.home'))
        flash('اسم المستخدم أو كلمة المرور خاطئة', 'error')
    return render_template('login.html')


@bp.route('/logout')
def logout():
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('auth.login'))
