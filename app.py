from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import hashlib
import sqlite3
import secrets
import os

app = Flask(__name__)
# 세션에 사용되는 비밀 키 설정
app.secret_key = secrets.token_hex(256)
# 세션 지속 시간 설정
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
# 세션 타입 설정
app.config['SESSION_TYPE'] = 'filesystem'
# 파일 타입 설정
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'hwp'}
# 프로젝트 루트 경로 설정
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'uploads')
# 파일 업로드 경로 설정
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 업로드된 파일이 허용된 확장자인지 확인하는 함수를 정의합니다.
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 파일 업로드 경로가 존재하지 않으면 생성
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    
def filename_sha_512_hash(data):
    # 데이터를 UTF-8 인코딩으로 변환하여 해싱합니다.
    encoded_data = data.encode('utf-8') + os.urandom(16)
    hashed_data = hashlib.sha512(encoded_data).hexdigest()
    return hashed_data


conn = sqlite3.connect('web.db', check_same_thread=False)
cursor = conn.cursor()

# 메인 페이지
@app.route('/', methods=['GET'])
def index():
    return render_template('profile.html')

# 프로필 페이지
@app.route('/profile', methods=['GET'])
def profile():
    return render_template('profile.html')

# 게시판 페이지
@app.route('/board', methods=['GET'])
def board():
    try:
        status = 1
        select_query = """
        SELECT id, title, username, modification_date FROM boards WHERE status = ?
        """
        cursor.execute(select_query, (status, ))
        posts = cursor.fetchall()
        return render_template('board.html', posts=posts)
    except sqlite3.InternalError:
        msg = "문제 발생"
        return render_template('profile.html', msg=msg)

# 게시글 페이지
@app.route('/view_post', methods=['GET'])
def view_post():
    try:
        post={}
        id = request.args.get('id', '', type=int)
        status = 1
        select_query = """
        SELECT title, username, content, modification_date FROM boards WHERE id = ? AND status = ?
        """
        cursor.execute(select_query, (id, status))
        post = cursor.fetchone()
        return render_template('view_post.html', post=post)
    except sqlite3.IntegrityError:
        msg = "게시글 없음"
        return render_template('board.html', msg=msg)

# 게시글 생성 기능
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'GET':
        return render_template('create_post.html')
    elif request.method == 'POST':
        try:
            title = request.form['title']
            content = request.form['content']
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
            
            # 파일 업로드 처리
            file = request.files['file']
            if file and allowed_file(file.filename):
                # 파일 크기 제한 설정 (최대 1MB)
                if len(file.read()) > 1024*1024*100:
                    msg = "파일 크기가 너무 큽니다. 최대 1MB까지 업로드 가능합니다."
                    return render_template('create_post.html', msg=msg)
                file.seek(0)  # 파일을 다시 읽을 수 있도록 커서 위치를 처음으로 이동시킴
                real_filename = file.filename
                hash_filename = filename_sha_512_hash(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], hash_filename))
            else:
                file_path = None
            
            # 회원 정보 데이터베이스에 삽입
            insert_query = """
            INSERT INTO boards (U_id, username, title, content, real_filename, hash_filename, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_query, (U_id, username, title, content, real_filename, hash_filename, status))
            conn.commit()
            return render_template('board.html')
        except sqlite3.IntegrityError:
            msg = "작성 실패"
            return render_template('create_post.html', msg=msg)

# 포트폴리오 페이지
@app.route('/portfolio', methods=['GET'])
def portfolio():
    return render_template('portfolio.html')

# CONTACT ME 페이지
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'GET':
        return render_template('contact.html')
    elif request.method == 'POST':
        try:
            U_id = session['id']
            username = session['username']
            title = request.form['title']
            email = request.form['email']
            message = request.form['message']
            status = 1
            if (title != None and email != None and message != None):
                # CONTACT 데이터베이스에 삽입
                insert_query = """
                INSERT INTO contact (U_id, username, title, email, message, status) 
                VALUES (?, ?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (U_id, username, title, email, message, status))
                conn.commit()
                return render_template('contact_list.html')
            else:
                msg = "입력값 없음"
                return render_template('contact.html', msg=msg)
        except sqlite3.IntegrityError:
            msg = "작성 실패"
            return render_template('contact.html', msg=msg)

# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        try:
            id = request.form['id']
            password = request.form['password']
            # 회원 정보 데이터베이스에서 검색
            select_query = """
            SELECT id, username, authority FROM members WHERE id = ? AND password = ?
            """
            cursor.execute(select_query, (id, password))
            user = cursor.fetchone()
            if user:
                # 세션에 사용자 정보 저장
                session['id'] = user[0]
                session['username'] = user[1]
                session['authority'] = user[2]
                return render_template('/profile.html')
            else:
                msg = "계정 불일치"
                return render_template('login.html', msg=msg)
        except sqlite3.IntegrityError:
            msg = "로그인 실패"
            return render_template('login.html', msg=msg)

# 회원가입 페이지
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    elif request.method == 'POST':
        try:
            fullname = request.form['fullname']
            username = request.form['username']
            id = request.form['id']
            password = request.form['password']
            confirmPassword = request.form['confirmPassword']
            gender = request.form['gender']
            phone = request.form['phone']
            email = request.form['email']
            authority = 1
            status = 1

            if(password == confirmPassword):
                # 회원 정보 데이터베이스에 삽입
                insert_query = """
                INSERT INTO members (fullname, username, id, password, gender, phone, email, authority, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (fullname, username, id, password, gender, phone, email, authority, status))
                conn.commit()
                return render_template('/login.html', msg=msg)
            else:
                msg = "비밀번호 불일치"
                return render_template('/register.html', msg=msg)
        except sqlite3.IntegrityError:
            msg = "이미 존재하는 회원 정보입니다."
            return render_template('/register.html', msg=msg)

# 로그아웃
@app.route('/logout', methods=['GET'])
def logout():
    if request.method == 'GET':
        try:
            session.clear()  # 세션에서 사용자 정보 삭제
            return render_template('/profile.html', msg=msg)
        except:
            msg = "로그아웃 실패"
            return render_template('/profile.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)