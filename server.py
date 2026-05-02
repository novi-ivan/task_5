from http.server import BaseHTTPRequestHandler, HTTPServer
from http import cookies
import urllib.parse
import mysql.connector
import re
import os
import html
import secrets
import string
import hashlib
from datetime import datetime

PREFIX = '/task_5'
PORT = 8083
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_CONFIG = {
    'host': 'localhost',
    'user': 'webuser',
    'password': '123456',
    'database': 'webform'
}

ALLOWED_LANGUAGES = {str(i) for i in range(1, 13)}
SESSIONS = {}


def load_file(filename):
    with open(os.path.join(BASE_DIR, filename), 'r', encoding='utf-8') as f:
        return f.read()


def escape(value):
    return html.escape(str(value), quote=True)


def encode_cookie_value(value):
    return urllib.parse.quote(str(value), safe='')


def decode_cookie_value(value):
    return urllib.parse.unquote(value)


def make_cookie_header(name, value, path, max_age=None):
    header = f'{name}={encode_cookie_value(value)}; Path={path}'
    if max_age is not None:
        header += f'; Max-Age={max_age}'
    return header


def make_delete_cookie_header(name, path):
    return f'{name}=; Path={path}; Max-Age=0'


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def password_hash(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def generate_random_string(length):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_password():
    return generate_random_string(10)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in [PREFIX, PREFIX + '/']:
            user_id = self.get_current_user_id()

            if user_id:
                form_data = self.load_user_form_data(user_id)
                self.render_form(form_data=form_data, errors={}, is_logged=True)
            else:
                cookie_data = self.get_cookie_values()
                form_data = self.extract_form_from_cookies(cookie_data)
                errors = self.extract_errors_from_cookies(cookie_data)
                clear_headers = self.build_clear_error_cookie_headers(cookie_data)
                self.render_form(form_data=form_data, errors=errors, extra_cookie_headers=clear_headers)

        elif self.path == PREFIX + '/login':
            self.render_login()

        elif self.path == PREFIX + '/logout':
            self.logout()

        elif self.path == PREFIX + '/style.css':
            self.send_css()

        else:
            self.send_404()

    def do_POST(self):
        if self.path == PREFIX + '/submit':
            self.handle_submit()
        elif self.path == PREFIX + '/login':
            self.handle_login()
        else:
            self.send_404()

    def handle_submit(self):
        form_data = self.read_form_data()
        errors = self.validate_form(form_data)

        if errors:
            if self.get_current_user_id():
                self.render_form(form_data=form_data, errors=errors, is_logged=True)
            else:
                self.redirect_with_error_cookies(form_data, errors)
            return

        user_id = self.get_current_user_id()

        if user_id:
            self.update_application(user_id, form_data)
            self.redirect(PREFIX + '/')
            return

        username = self.generate_unique_username()
        plain_password = generate_password()
        new_user_id = self.insert_application(form_data, username, password_hash(plain_password))

        self.redirect_with_success_cookies(form_data, username, plain_password)

    def read_form_data(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(body)

        return {
            'name': data.get('name', [''])[0].strip(),
            'phone': data.get('phone', [''])[0].strip(),
            'email': data.get('email', [''])[0].strip(),
            'birth': data.get('birth', [''])[0].strip(),
            'gender': data.get('gender', [''])[0].strip(),
            'bio': data.get('bio', [''])[0].strip(),
            'agreement': 'agreement' in data,
            'languages': data.get('languages[]', [])
        }

    def validate_form(self, form_data):
        errors = {}

        if not re.fullmatch(r'[A-Za-zА-Яа-яЁё\s]{1,150}', form_data['name']):
            errors['name'] = 'Допустимы только буквы и пробелы, длина не более 150 символов.'

        if not re.fullmatch(r'\+?[0-9]{10,15}', form_data['phone']):
            errors['phone'] = 'Допустимы только цифры, возможно начало с +, длина от 10 до 15 символов.'

        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', form_data['email']):
            errors['email'] = 'Введите корректный e-mail.'

        if not form_data['birth']:
            errors['birth'] = 'Укажите дату рождения.'
        else:
            try:
                birth_date = datetime.strptime(form_data['birth'], '%Y-%m-%d').date()
                if birth_date > datetime.today().date():
                    errors['birth'] = 'Дата рождения не может быть из будущего.'
            except ValueError:
                errors['birth'] = 'Введите корректную дату рождения.'

        if form_data['gender'] not in ['male', 'female']:
            errors['gender'] = 'Выберите пол.'

        if not form_data['languages']:
            errors['languages'] = 'Выберите хотя бы один язык программирования.'
        else:
            for lang_id in form_data['languages']:
                if lang_id not in ALLOWED_LANGUAGES:
                    errors['languages'] = 'Можно выбирать только языки из списка.'
                    break

        if not form_data['bio']:
            errors['bio'] = 'Биография не должна быть пустой.'
        elif not re.fullmatch(r"[\wА-Яа-яЁё\s.,!?;:()\-\"']{1,5000}", form_data['bio']):
            errors['bio'] = 'Биография содержит недопустимые символы.'

        if not form_data['agreement']:
            errors['agreement'] = 'Нужно подтвердить ознакомление с контрактом.'

        return errors

    def insert_application(self, form_data, username, password_hash_value):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO application
            (full_name, phone, email, birth_date, gender, biography, contract_accepted, username, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            form_data['name'],
            form_data['phone'],
            form_data['email'],
            form_data['birth'],
            form_data['gender'],
            form_data['bio'],
            int(form_data['agreement']),
            username,
            password_hash_value
        ))

        application_id = cursor.lastrowid

        for lang_id in form_data['languages']:
            cursor.execute("""
                INSERT INTO application_languages (application_id, language_id)
                VALUES (%s, %s)
            """, (application_id, int(lang_id)))

        conn.commit()
        cursor.close()
        conn.close()

        return application_id

    def update_application(self, user_id, form_data):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE application
            SET full_name=%s,
                phone=%s,
                email=%s,
                birth_date=%s,
                gender=%s,
                biography=%s,
                contract_accepted=%s
            WHERE id=%s
        """, (
            form_data['name'],
            form_data['phone'],
            form_data['email'],
            form_data['birth'],
            form_data['gender'],
            form_data['bio'],
            int(form_data['agreement']),
            user_id
        ))

        cursor.execute("""
            DELETE FROM application_languages
            WHERE application_id=%s
        """, (user_id,))

        for lang_id in form_data['languages']:
            cursor.execute("""
                INSERT INTO application_languages (application_id, language_id)
                VALUES (%s, %s)
            """, (user_id, int(lang_id)))

        conn.commit()
        cursor.close()
        conn.close()

    def generate_unique_username(self):
        conn = get_db_connection()
        cursor = conn.cursor()

        while True:
            username = 'user_' + generate_random_string(8).lower()
            cursor.execute("SELECT id FROM application WHERE username=%s", (username,))
            if cursor.fetchone() is None:
                cursor.close()
                conn.close()
                return username

    def handle_login(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(body)

        username = data.get('username', [''])[0].strip()
        password = data.get('password', [''])[0].strip()

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, password_hash
            FROM application
            WHERE username=%s
        """, (username,))

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user or user['password_hash'] != password_hash(password):
            self.render_login(error='Неверный логин или пароль.')
            return

        session_id = generate_random_string(32)
        SESSIONS[session_id] = user['id']

        self.send_response(302)
        self.send_header('Set-Cookie', make_cookie_header('session_id', session_id, PREFIX + '/'))
        self.send_header('Location', PREFIX + '/')
        self.end_headers()

    def get_current_user_id(self):
        cookie_data = self.get_cookie_values()
        session_id = cookie_data.get('session_id', '')
        return SESSIONS.get(session_id)

    def logout(self):
        cookie_data = self.get_cookie_values()
        session_id = cookie_data.get('session_id', '')

        if session_id in SESSIONS:
            del SESSIONS[session_id]

        self.send_response(302)
        self.send_header('Set-Cookie', make_delete_cookie_header('session_id', PREFIX + '/'))
        self.send_header('Location', PREFIX + '/')
        self.end_headers()

    def load_user_form_data(self, user_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT full_name, phone, email, birth_date, gender, biography, contract_accepted
            FROM application
            WHERE id=%s
        """, (user_id,))
        row = cursor.fetchone()

        cursor.execute("""
            SELECT language_id
            FROM application_languages
            WHERE application_id=%s
        """, (user_id,))
        languages = [str(x['language_id']) for x in cursor.fetchall()]

        cursor.close()
        conn.close()

        return {
            'name': row['full_name'],
            'phone': row['phone'],
            'email': row['email'],
            'birth': str(row['birth_date']),
            'gender': row['gender'],
            'bio': row['biography'],
            'agreement': bool(row['contract_accepted']),
            'languages': languages
        }

    def get_cookie_values(self):
        if 'Cookie' not in self.headers:
            return {}

        cookie = cookies.SimpleCookie(self.headers['Cookie'])
        result = {}

        for key in cookie:
            result[key] = decode_cookie_value(cookie[key].value)

        return result

    def extract_form_from_cookies(self, cookie_data):
        languages_raw = cookie_data.get('form_languages', '')
        languages = [x for x in languages_raw.split(',') if x] if languages_raw else []

        return {
            'name': cookie_data.get('form_name', ''),
            'phone': cookie_data.get('form_phone', ''),
            'email': cookie_data.get('form_email', ''),
            'birth': cookie_data.get('form_birth', ''),
            'gender': cookie_data.get('form_gender', ''),
            'bio': cookie_data.get('form_bio', ''),
            'agreement': cookie_data.get('form_agreement', '') == '1',
            'languages': languages
        }

    def extract_errors_from_cookies(self, cookie_data):
        errors = {}
        for key, value in cookie_data.items():
            if key.startswith('error_') and value:
                errors[key[len('error_'):]] = value
        return errors

    def build_clear_error_cookie_headers(self, cookie_data):
        headers = []
        for key in cookie_data.keys():
            if key.startswith('error_'):
                headers.append(make_delete_cookie_header(key, PREFIX + '/'))
        return headers

    def build_form_cookie_headers(self, form_data, persistent):
        max_age = 60 * 60 * 24 * 365 if persistent else None

        cookie_map = {
            'form_name': form_data['name'],
            'form_phone': form_data['phone'],
            'form_email': form_data['email'],
            'form_birth': form_data['birth'],
            'form_gender': form_data['gender'],
            'form_bio': form_data['bio'],
            'form_agreement': '1' if form_data['agreement'] else '0',
            'form_languages': ','.join(form_data['languages'])
        }

        return [
            make_cookie_header(key, value, PREFIX + '/', max_age)
            for key, value in cookie_map.items()
        ]

    def redirect_with_error_cookies(self, form_data, errors):
        self.send_response(302)

        for header in self.build_form_cookie_headers(form_data, persistent=False):
            self.send_header('Set-Cookie', header)

        for key, message in errors.items():
            self.send_header('Set-Cookie', make_cookie_header('error_' + key, message, PREFIX + '/'))

        self.send_header('Location', PREFIX + '/')
        self.end_headers()

    def redirect_with_success_cookies(self, form_data, username, password):
        self.send_response(200)

        for header in self.build_form_cookie_headers(form_data, persistent=True):
            self.send_header('Set-Cookie', header)

        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

        page = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="color-scheme" content="dark">
    <title>Данные сохранены</title>
    <link rel="stylesheet" href="{PREFIX}/style.css">
</head>
<body>
    <div class="message-box">
        <div class="success-box">Данные успешно сохранены.</div>
        <h1>Ваши данные для входа</h1>
        <p>Сохраните их. Пароль показывается только один раз.</p>
        <div class="credentials">
            <p><strong>Логин:</strong> {escape(username)}</p>
            <p><strong>Пароль:</strong> {escape(password)}</p>
        </div>
        <div class="message-actions">
            <a href="{PREFIX}/login">Войти</a>
            <a href="{PREFIX}/">Вернуться к форме</a>
        </div>
    </div>
</body>
</html>"""
        self.wfile.write(page.encode('utf-8'))

    def render_form(self, form_data, errors, extra_cookie_headers=None, is_logged=False):
        if extra_cookie_headers is None:
            extra_cookie_headers = []

        template = load_file('form.html')

        replacements = {
            '{{prefix}}': PREFIX,
            '{{auth_block}}': self.render_auth_block(is_logged),
            '{{form_title}}': 'Редактирование данных' if is_logged else 'Форма заявки',
            '{{button_text}}': 'Сохранить изменения' if is_logged else 'Сохранить',

            '{{name}}': escape(form_data['name']),
            '{{phone}}': escape(form_data['phone']),
            '{{email}}': escape(form_data['email']),
            '{{birth}}': escape(form_data['birth']),
            '{{bio}}': escape(form_data['bio']),

            '{{male_checked}}': 'checked' if form_data['gender'] == 'male' else '',
            '{{female_checked}}': 'checked' if form_data['gender'] == 'female' else '',
            '{{agreement_checked}}': 'checked' if form_data['agreement'] else '',

            '{{name_error_block}}': self.build_error(errors, 'name'),
            '{{phone_error_block}}': self.build_error(errors, 'phone'),
            '{{email_error_block}}': self.build_error(errors, 'email'),
            '{{birth_error_block}}': self.build_error(errors, 'birth'),
            '{{gender_error_block}}': self.build_error(errors, 'gender'),
            '{{languages_error_block}}': self.build_error(errors, 'languages'),
            '{{bio_error_block}}': self.build_error(errors, 'bio'),
            '{{agreement_error_block}}': self.build_error(errors, 'agreement'),

            '{{name_error_class}}': 'input-error' if 'name' in errors else '',
            '{{phone_error_class}}': 'input-error' if 'phone' in errors else '',
            '{{email_error_class}}': 'input-error' if 'email' in errors else '',
            '{{birth_error_class}}': 'input-error' if 'birth' in errors else '',
            '{{gender_error_class}}': 'group-error' if 'gender' in errors else '',
            '{{languages_error_class}}': 'input-error' if 'languages' in errors else '',
            '{{bio_error_class}}': 'input-error' if 'bio' in errors else '',
            '{{agreement_error_class}}': 'group-error' if 'agreement' in errors else '',
        }

        for i in range(1, 13):
            replacements[f'{{{{lang_{i}}}}}'] = 'selected' if str(i) in form_data['languages'] else ''

        for key, value in replacements.items():
            template = template.replace(key, value)

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')

        for header in extra_cookie_headers:
            self.send_header('Set-Cookie', header)

        self.end_headers()
        self.wfile.write(template.encode('utf-8'))

    def render_auth_block(self, is_logged):
        if is_logged:
            return f'<a class="top-link" href="{PREFIX}/logout">Выйти</a>'
        return f'<a class="top-link" href="{PREFIX}/login">Войти для редактирования</a>'

    def render_login(self, error=''):
        error_html = f'<div class="error-box">{escape(error)}</div>' if error else ''

        page = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="color-scheme" content="dark">
    <title>Вход</title>
    <link rel="stylesheet" href="{PREFIX}/style.css">
</head>
<body>
    <div class="form-wrapper small">
        <h1>Вход</h1>
        {error_html}
        <form method="POST" action="{PREFIX}/login">
            <div class="form-group">
                <label>Логин</label>
                <input type="text" name="username">
            </div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="password" name="password">
            </div>
            <button type="submit">Войти</button>
        </form>
        <p><a class="top-link" href="{PREFIX}/">Вернуться к форме</a></p>
    </div>
</body>
</html>"""
        self.send_html(page)

    def build_error(self, errors, field):
        if field not in errors:
            return ''
        return f'<div class="field-error">{escape(errors[field])}</div>'

    def redirect(self, url):
        self.send_response(302)
        self.send_header('Location', url)
        self.end_headers()

    def send_css(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/css; charset=utf-8')
        self.end_headers()
        self.wfile.write(load_file('style.css').encode('utf-8'))

    def send_html(self, text, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(text.encode('utf-8'))

    def send_404(self):
        self.send_html('<h1>404</h1>', status=404)


def run():
    server = HTTPServer(('127.0.0.1', PORT), Handler)
    print(f'Server started on http://127.0.0.1:{PORT}{PREFIX}/')
    server.serve_forever()


if __name__ == '__main__':
    run()