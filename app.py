from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 메인 페이지
@app.route('/')
def index():
    return render_template('profile.html')

# 프로필 페이지
@app.route('/profile')
def profile():
    return render_template('profile.html')

# 게시판 페이지
@app.route('/board')
def board():
    return render_template('board.html')

@app.route('/create_post')
def create_post():
    return render_template('create_post.html')

# 포트폴리오 페이지
@app.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')

# CONTACT ME 페이지
@app.route('/contact')
def contact():
    return render_template('contact.html')

# 로그인 페이지
@app.route('/login')
def login():
    return render_template('login.html')

# 회원가입 페이지
@app.route('/register')
def register():
    return render_template('register.html')

# 로그아웃
@app.route('/logout')
def logout():
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
