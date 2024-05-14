# encoding=utf8
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
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
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'hwp'}
# 프로젝트 루트 경로 설정
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
print(PROJECT_ROOT)
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'uploads')
print(UPLOAD_FOLDER)
# 파일 업로드 경로 설정
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 업로드된 파일이 허용된 확장자인지 확인하는 함수를 정의합니다.
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 파일 업로드 경로가 존재하지 않으면 생성
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.config.update(
    DEBUG=True,
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='your_gmail@gmail.com',
    MAIL_PASSWORD='app_key',
)


def filename_sha_512_hash(data):
    encoded_data = data.encode('utf-8') + os.urandom(16)
    hashed_data = hashlib.sha512(encoded_data).hexdigest()
    return hashed_data

def password_sha_512_hash(data):
    encoded_data = data.encode('utf-8')
    hashed_data = hashlib.sha512(encoded_data).hexdigest()
    return hashed_data

def send_confirmation_email(email, token):
    try:
        mail = Mail(app)
        msg = Message('[KRhound] 이메일 인증 번호', sender='your_gmail@gmail.com', recipients=[email])
        msg.body = '안녕하세요. KRhound 입니다.\n인증 번호를 입력하여 이메일 인증을 완료해 주세요.\n인증 번호 : /nhttp://127.0.0.1:5000/confirm/{}'.format(str(token))
        mail.send(msg)
        return True
    except:
        return False

def create_directory_if_not_exists(directory_path):
    # 디렉토리가 존재하지 않으면 생성
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"Create succesfully : {directory_path}")
    else:
        print(f"Directory exists : {directory_path}")

conn = sqlite3.connect('../database/web.db', check_same_thread=False)
cursor = conn.cursor()
# -------------------------------------------------------------

# 메인 페이지
# 프로필 페이지
@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
@app.route('/profile', methods=['GET'])
def profile():
    return render_template('profile.html')

# 포트폴리오 페이지
@app.route('/portfolio', methods=['GET'])
def portfolio():
    return render_template('portfolio.html')

# 에러 페이지
@app.route('/error', methods=['GET'])
def error():
    error = request.args.get('error', None, type=str)
    if error is not None:
        return render_template('error.html', error=error)
    
# -------------------------------------------------------------

# 게시판 페이지
@app.route('/board', methods=['GET'])
def board():
    try:
        status = 1
        select_query = """
        SELECT id, title, username, modification_date 
        FROM boards WHERE status = ? ORDER BY modification_date DESC;
        """
        cursor.execute(select_query, (status, ))
        posts = cursor.fetchall()
        return render_template('board.html', posts=posts)
    except:
        msg = "Bulletin board loading failure."
        return redirect(url_for('error', error=error))

# 게시글 보기 페이지
@app.route('/view_post', methods=['GET'])
def view_post():
    if request.method == 'GET':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            id = request.args.get('id', '', type=int)
            status = 1
            select_query = """
            SELECT id, title, username, content, real_filename, modification_date 
            FROM boards WHERE id = ? AND status = ?
            """
            cursor.execute(select_query, (id, status))
            post = cursor.fetchone()
            select_query = """
            SELECT id, username, content, modification_date 
            FROM comments WHERE B_id = ? AND status = ? ORDER BY modification_date DESC;
            """
            cursor.execute(select_query, (id, status))
            comments = cursor.fetchall()
            return render_template('view_post.html', post=post, comments=comments)
        except:
            error = "Unusual approach."
            return redirect(url_for('error', error=error))
    
# 게시글 수정 페이지
@app.route('/update_post', methods=['GET', 'POST'])
def update_post():
    if request.method == "GET":
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
            select_query = """
            SELECT id, title, username, content, real_filename 
            FROM boards WHERE id = ? AND U_id = ? AND status = ?
            """
            cursor.execute(select_query, (id, U_id, status))
            post = cursor.fetchone()
            return render_template('edit_post.html', post=post)
        except:
            error = "Failed to edit post."
            return redirect(url_for('error', error=error)) 
    elif request.method == 'POST':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
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
                if len(file.read()) > 1024*1024*30:
                    msg = "파일 크기가 너무 큽니다. 최대 30MB까지 업로드 가능합니다."
                    return render_template('create_post.html', msg=msg)
                file.seek(0)  # 파일을 다시 읽을 수 있도록 커서 위치를 처음으로 이동시킴
                real_filename = file.filename
                hash_filename = filename_sha_512_hash(file.filename)
                file_path = app.config['UPLOAD_FOLDER']+'/'+str(id)+'/'
                create_directory_if_not_exists(file_path)
                file.save(os.path.join(file_path, hash_filename))
            else:
                real_filename = None
                hash_filename = None
            if real_filename is None and hash_filename is None:
                update_query = """
                UPDATE boards 
                SET title = ?, content = ?
                WHERE id = ? AND username = ? AND status = ?
                """
                cursor.execute(update_query, (title, content, id, username, status))
                conn.commit()
            else:
                update_query = """
                UPDATE boards 
                SET title = ?, content = ?, real_filename = ?, hash_filename = ?
                WHERE id = ? AND username = ? AND status = ?
                """
                cursor.execute(update_query, (title, content, real_filename, hash_filename, id, username, status))
                conn.commit()
            return redirect(url_for('view_post', id=id))
        except:
            error = "Failed to edit post."
            return redirect(url_for('error', error=error))

# 게시글 삭제 페이지
@app.route('/delete_post', methods=['GET'])
def delete_post():
    if request.method == 'GET':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            status = 0
            update_query = """
            UPDATE boards 
            SET status = ? 
            WHERE id = ?
            """
            cursor.execute(update_query, (status, id))
            conn.commit()
            return redirect(url_for('board'))
        except:
            error = "Failed to delete post."
            return redirect(url_for('error', error=error))

# 게시글 생성 기능
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'GET':
        if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
        return render_template('create_post.html')
    elif request.method == 'POST':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            title = request.form['title']
            content = request.form['content']
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
            file = request.files['file']
            
            # 회원 정보 데이터베이스에 삽입
            insert_query = """
            INSERT INTO boards (U_id, username, title, content, real_filename, hash_filename, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            
             # 파일 업로드 처리
            if file and allowed_file(file.filename):
                # 파일 크기 제한 설정 (최대 100MB)
                if len(file.read()) > 1024*1024*100:
                    msg = "파일 크기가 너무 큽니다. 최대 100MB까지 업로드 가능합니다."
                    return render_template('create_post.html', msg=msg)
                file.seek(0)  # 파일을 다시 읽을 수 있도록 커서 위치를 처음으로 이동시킴
                real_filename = file.filename
                hash_filename = filename_sha_512_hash(file.filename)
                cursor.execute(insert_query, (U_id, username, title, content, real_filename, hash_filename, status))
                conn.commit()
                id = cursor.lastrowid
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(id))
                print(hash_filename)
                create_directory_if_not_exists(file_path)
                file.save(os.path.join(file_path, hash_filename))
                return redirect(url_for('view_post', id=id))
            elif file and allowed_file(file.filename) == False:
                error = "Not allowed file exention."
                return redirect(url_for('error', error=error))
            else:
                real_filename = None
                hash_filename = None
                cursor.execute(insert_query, (U_id, username, title, content, real_filename, hash_filename, status))
                conn.commit()
                id = cursor.lastrowid
                return redirect(url_for('view_post', id=id))
        except Exception:
            error = "Creation failed."
            return redirect(url_for('error', error=error))

# 댓글 작성
@app.route('/create_comment', methods=['POST'])
def create_comment():
    if request.method == 'POST':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            content = request.form['content']
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
            select_query = """
            SELECT status 
            FROM boards WHERE id = ?
            """
            cursor.execute(select_query, (id, ))
            board = cursor.fetchone()
            if board[0] == 1:
                insert_query = """
                INSERT INTO comments (U_id, username, content, status, B_id) 
                VALUES (?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (U_id, username, content, status, id))
                conn.commit()
                return redirect(url_for('view_post', id=id))
            elif board[0] == 0:
                error = "Creation failed."
                return redirect(url_for('error', error=error))
        except Exception:
            error = "Creation failed."
            return redirect(url_for('error', error=error))
        
# 게시글 삭제
@app.route('/delete_comment', methods=['GET'])
def delete_comment():
    if request.method == 'GET':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            B_id = request.args.get('B_id', '', type=int)
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            update_query = """
            UPDATE comments 
            SET status = 0 
            WHERE id = ? AND username = ? AND status = 1
            """
            cursor.execute(update_query, (id, username))
            conn.commit()
            return redirect(url_for('view_post', id=B_id))
        except:
            error = "Failed to delete post."
            return redirect(url_for('error', error=error))

# -------------------------------------------------------------

# 다운로드 페이지
@app.route('/download/<id>/<filename>', methods=['GET'])
def download(id, filename):
    try:
        if 'username' not in session:
            error = "Login required."
            return redirect(url_for('error', error=error))
        status = 1
        select_query = """
        SELECT real_filename, hash_filename 
        FROM boards WHERE id = ? AND real_filename = ? AND status = ?
        """
        cursor.execute(select_query, (id, filename, status))
        file = cursor.fetchone()
        real_filename = file[0]
        hash_filename = file[1]
        # 파일 경로 설정
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], id, hash_filename)
        # 파일이 존재하는지 확인하고 다운로드
        if os.path.exists(file_path):
            return send_file(file_path, download_name=real_filename, as_attachment=True)
        else:
            error='File not found.'
            return redirect(url_for('error', error=error))
    except Exception:
        error = "Download failed."
        return redirect(url_for('error', error=error))
    
# -------------------------------------------------------------

# Contact Me 게시판 페이지
@app.route('/contact', methods=['GET'])
def contact():
    try:
        status = 1
        select_query = """
        SELECT id, username, title, email, response_date, registration_date 
        FROM contacts WHERE status = ? ORDER BY registration_date DESC;
        """
        cursor.execute(select_query, (status, ))
        contacts = cursor.fetchall()
        return render_template('contact.html', contacts=contacts)
    except Exception:
        msg = "Bulletin board loading failure."
        return redirect(url_for('error', error=error))
    

# CONTACT ME 생성 페이지
@app.route('/create_contact', methods=['GET', 'POST'])
def create_contact():
    if request.method == 'GET':
        if 'username' not in session:
            error = "Login required."
            return redirect(url_for('error', error=error))
        return render_template('create_contact.html')
    elif request.method == 'POST':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            U_id = session['id']
            username = session['username']
            title = request.form['title']
            email = request.form['email']
            message = request.form['message']
            status = 1
            if (title != None and email != None and message != None):
                # CONTACT 데이터베이스에 삽입
                insert_query = """
                INSERT INTO contacts (U_id, username, title, email, message, status) 
                VALUES (?, ?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (U_id, username, title, email, message, status))
                conn.commit()
                return redirect(url_for('contact'))
            else:
                error = "No input."
                return redirect(url_for('error', error=error))
        except Exception:
            error = "Creation failed."
            return redirect(url_for('error', error=error))
                
# contact 게시글 보기 페이지
@app.route('/view_contact', methods=['GET'])
def view_contact():
    if request.method == 'GET':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            id = request.args.get('id', '', type=int)
            status = 1
            if authority == 1:
                select_query = """
                SELECT id, title, username, email, message, response_date, registration_date 
                FROM contacts WHERE id = ? AND username = ? AND status = ?
                """
                cursor.execute(select_query, (id, username, status))
                contact = cursor.fetchone()
            elif authority == 2:
                select_query = """
                SELECT id, title, username, email, message, response_date, registration_date 
                FROM contacts WHERE id = ? AND status = ?
                """
                cursor.execute(select_query, (id, status))
                contact = cursor.fetchone()
            return render_template('view_contact.html', contact=contact)
        except Exception:
            error = "Unusual approach."
            return redirect(url_for('error', error=error))
        
# contact 게시글 삭제 페이지
@app.route('/delete_contact', methods=['GET'])
def delete_contact():
    if request.method == 'GET':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            status = 0
            username = session['username']
            update_query = """
            UPDATE contacts 
            SET status = ? 
            WHERE id = ? and username = ?
            """
            cursor.execute(update_query, (status, id, username))
            conn.commit()
            return redirect(url_for('contact'))
        except:
            error = "Failed to delete contact."
            return redirect(url_for('error', error=error))
        
# 게시글 수정 페이지
@app.route('/update_contact', methods=['GET', 'POST'])
def update_contact():
    if request.method == "GET":
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
            select_query = """
            SELECT id, username, title, email, message 
            FROM contacts WHERE id = ? AND username = ? AND status = ?
            """
            cursor.execute(select_query, (id, username, status))
            contact = cursor.fetchone()
            return render_template('edit_contact.html', contact=contact)
        except:
            error = "Failed to edit contact."
            return redirect(url_for('error', error=error))
    elif request.method == 'POST':
        try:
            if 'username' not in session:
                error = "Login required."
                return redirect(url_for('error', error=error))
            id = request.args.get('id', '', type=int)
            title = request.form['title']
            email = request.form['email']
            message = request.form['message']
            U_id = session['id']
            username = session['username']
            authority = session['authority']
            status = 1
        
            update_query = """
            UPDATE contacts 
            SET title = ?, email = ?, message = ? 
            WHERE id = ? AND username = ? AND status = ?
            """
            cursor.execute(update_query, (title, email, message, id, username, status))
            conn.commit()
            return redirect(url_for('view_contact', id=id))
        except:
            error = "Failed to edit contact."
            return redirect(url_for('error', error=error))
        
# -------------------------------------------------------------

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
            SELECT id, username, authority 
            FROM members WHERE id = ? AND password = ?
            """
            cursor.execute(select_query, (id, password))
            user = cursor.fetchone()
            if user[2] == 0:
                return redirect(url_for('send_email', id=user[0]))
            elif user:
                # 세션에 사용자 정보 저장
                session['id'] = user[0]
                session['username'] = user[1]
                session['authority'] = user[2]
                return redirect(url_for('profile'))
            else:
                error = "Account mismatch."
                return redirect(url_for('error', error=error))
        except Exception:
            error = "Login failed."
            return redirect(url_for('error', error=error))

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
            authority = 0
            status = 1

            if(password == confirmPassword):
                # 회원 정보 데이터베이스에 삽입
                insert_query = """
                INSERT INTO members (fullname, username, id, password, gender, phone, email, authority, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (fullname, username, id, password, gender, phone, email, authority, status))
                conn.commit()
                msg = "Membership registration successful!"
                return render_template('/login.html', msg=msg)
            else:
                msg = "비밀번호 불일치"
                return render_template('/register.html', msg=msg)
        except Exception:
            msg = "이미 존재하는 회원 정보입니다."
            return render_template('/register.html', msg=msg)
        
# 로그아웃
@app.route('/logout', methods=['GET'])
def logout():
    if request.method == 'GET':
        try:
            session.clear()  # 세션에서 사용자 정보 삭제
            return render_template('/profile.html')
        except:
            msg = "Logout failed."
            return render_template('/profile.html', msg=msg)
        
# -------------------------------------------------------------
        
@app.route('/send_email/<id>', methods=['GET', 'POST'])
def send_email(id):
    if request.method == 'GET':
        try:
            select_query = """
            SELECT id, username, email, authority
            FROM members WHERE id = ?
            """
            cursor.execute(select_query, (id, ))
            user = cursor.fetchone()
            # 이메일 토큰 생성 및 저장
            if user[3] == 0:
                token = secrets.token_hex(256)
                print(token)
                insert_query = """
                INSERT INTO verify (U_id, username, email, token) 
                VALUES (?, ?, ?, ?)
                """
                cursor.execute(insert_query, (user[0], user[1], user[2], token))
                conn.commit()
                # 이메일에 토큰 전송
                print(send_confirmation_email(user[2], token))
                msg = "Authentication email sent successfully."
                return redirect(url_for('verify_email', msg=msg))
            else:
                error = "Failed to send authentication email."
                return redirect(url_for('error', error=error))
        except Exception:
            error = "Failed to send authentication email."
            return redirect(url_for('error', error=error))

@app.route('/verify_email/<msg>', methods=['GET'])
def verify_email(msg):
    return render_template('verify_email.html', verify_msg=msg)


@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        authority = 1
        select_query = """
        SELECT U_id, username, email
        FROM verify WHERE token = ?
        """
        cursor.execute(select_query, (token, ))
        user = cursor.fetchone()
        print(user)
        update_query = """
        UPDATE members 
        SET authority = 1
        WHERE id = ? AND username = ? AND email = ?
        """
        cursor.execute(update_query, (user[0], user[1], user[2]))
        conn.commit()
        msg = "Authentication successful."
        return redirect(url_for('verify_email', msg=msg))
    except:
        error = "Authentication failed."
        return redirect(url_for('error', error=error))

# -------------------------------------------------------------

# 관리자 페이지 구현
@app.route('/ed9465dea93268e8', methods=['GET'])
def admin():
    return render_template('krhound.html')

if __name__ == '__main__':
    app.run(debug=True)