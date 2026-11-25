import ssl

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
import mysql.connector
from wtforms.validators import DataRequired
from functools import wraps
from datetime import datetime, timedelta
import os
import secrets

# Helper to automatically load .env without external dependencies
def load_env():
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        key = key.strip()
                        val = val.strip().strip('"').strip("'")
                        if val != "":
                            os.environ[key] = val
        except Exception as e:
            print(f"Error loading .env: {e}")

load_env()

app = Flask(__name__)
app.config["SECRET_KEY"] = "my-secret-key-123"

# Database Connection Helper with automatic reconnection
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='1234',
    database='it_help_desk'
)

def get_db():
    global conn
    try:
        if not conn.is_connected():
            conn.reconnect(attempts=3, delay=1)
    except Exception:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='1234',
            database='it_help_desk'
        )
    return conn

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in with an administrator account to continue.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access restricted: Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

import re
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

class newissue(FlaskForm):
    title = StringField(
        'Title',
        validators=[
            DataRequired(message="Issue title is required."),
            Length(min=5, max=150, message="Title must be between 5 and 150 characters.")
        ]
    )
    category = SelectField(
        "Category",
        choices=[],
        coerce=int,
        validators=[DataRequired(message="Please select a category.")]
    )
    description = TextAreaField(
        'Description',
        validators=[
            DataRequired(message="Issue description is required."),
            Length(min=10, max=2000, message="Description must be at least 10 characters long.")
        ]
    )
    submit = SubmitField('Submit Issue')

class registerform(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=50, message="Username must be between 3 and 50 characters.")
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(message="Email address is required."),
            Regexp(EMAIL_REGEX, message="Please enter a valid email format (e.g. name@example.com)."),
            Length(max=120, message="Email must be less than 120 characters.")
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=6, max=100, message="Password must be at least 6 characters long.")
        ]
    )
    submit = SubmitField('Register')

class loginform(FlaskForm):
    email = StringField(
        'Email',
        validators=[
            DataRequired(message="Email address is required."),
            Regexp(EMAIL_REGEX, message="Please enter a valid email address.")
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required.")
        ]
    )
    submit = SubmitField('Login')

class forgotpasswordform(FlaskForm):
    email = StringField(
        'Registered Email',
        validators=[
            DataRequired(message="Please enter your registered email address."),
            Regexp(EMAIL_REGEX, message="Please enter a valid email format (e.g. user@domain.com).")
        ]
    )
    submit = SubmitField('Send OTP & Passkey')

class verifyotpform(FlaskForm):
    otp = StringField(
        '6-Digit OTP or Passkey',
        validators=[
            DataRequired(message="Please enter your 6-digit OTP or Passkey.")
        ]
    )
    submit = SubmitField('Verify & Continue')

class resetpasswordform(FlaskForm):
    password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message="New password is required."),
            Length(min=4, max=100, message="Password must be at least 4 characters long.")
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message="Please confirm your new password.")
        ]
    )
    submit = SubmitField('Update Password')

def send_reset_email(to_email, otp, passkey):
    """
    Sends email via SMTP (HTML + plain text fallback) if configured in .env; logs notice if unconfigured.
    """
    load_env()
    reset_link = f"http://127.0.0.1:5000/reset-password?passkey={passkey}&email={to_email}"
    
    smtp_server = os.environ.get('SMTP_SERVER', '').strip()
    smtp_port_raw = os.environ.get('SMTP_PORT', '587').strip()
    smtp_port = int(smtp_port_raw) if smtp_port_raw.isdigit() else 587
    smtp_user = os.environ.get('SMTP_USER', '').strip()
    smtp_pass = os.environ.get('SMTP_PASSWORD', '').strip()
    from_name = os.environ.get('SMTP_FROM_NAME', 'IT Help Desk Support').strip()

    # Log to terminal console for server auditing (never displayed on client web UI)
    print("\n" + "=" * 60)
    print(f"🔒 [PASSWORD RESET REQUEST - SERVER LOG]")
    print(f"Recipient: {to_email}")
    print(f"6-Digit OTP: {otp} | Reset Passkey: {passkey[:8]}... (Valid for 15 mins)")
    if not (smtp_server and smtp_user and smtp_pass):
        print(f"⚠️ Notice: Real email not sent because SMTP_USER / SMTP_PASSWORD in .env are empty.")
    print("=" * 60 + "\n")

    if smtp_server and smtp_user and smtp_pass:
        try:
            import smtplib
            from email.message import EmailMessage

            msg = EmailMessage()
            msg['Subject'] = "IT Help Desk - Password Reset Code & Passkey"
            msg['From'] = f"{from_name} <{smtp_user}>"
            msg['To'] = to_email

            # Plain text fallback
            plain_body = (
                f"Hello,\n\n"
                f"A password reset request was initiated for your IT Help Desk account.\n\n"
                f"Your 6-Digit Verification Code: {otp}\n"
                f"Your Reset Passkey: {passkey}\n\n"
                f"Or use this direct reset link:\n{reset_link}\n\n"
                f"This code will expire in 15 minutes.\n"
                f"If you did not request this, please disregard this email.\n\n"
                f"Best,\nIT Help Desk Team"
            )
            msg.set_content(plain_body)

            # Modern Cyberpunk HTML email version
            html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #071427; color: #eef3fb; margin: 0; padding: 24px; }}
    .card {{ max-width: 520px; margin: 0 auto; background: #0f2440; border: 1px solid #1a3c66; border-radius: 12px; padding: 32px; box-shadow: 0 16px 36px rgba(0,0,0,0.4); }}
    .logo {{ color: #2dd4bf; font-size: 20px; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 24px; }}
    .title {{ font-size: 22px; font-weight: 700; color: #ffffff; margin: 0 0 12px; }}
    .text {{ font-size: 14.5px; line-height: 1.6; color: #9bb2ce; margin: 0 0 20px; }}
    .otp-box {{ background: #071427; border: 1.5px solid #2dd4bf; border-radius: 10px; padding: 18px; text-align: center; margin: 24px 0; }}
    .otp-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #2dd4bf; margin-bottom: 6px; font-weight: 600; }}
    .otp-code {{ font-family: 'Courier New', monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #ffffff; margin: 0; }}
    .passkey-box {{ background: rgba(255, 180, 84, 0.08); border: 1px dashed rgba(255, 180, 84, 0.4); border-radius: 8px; padding: 12px; font-size: 12px; color: #ffb454; word-break: break-all; margin-bottom: 22px; }}
    .btn {{ display: block; text-align: center; background: #2dd4bf; color: #04231f !important; font-weight: 700; font-size: 14px; text-decoration: none; padding: 13px 24px; border-radius: 8px; margin: 20px 0; }}
    .footer {{ font-size: 12px; color: #627d9e; margin-top: 26px; border-top: 1px solid #1a3c66; padding-top: 16px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">⚡ IT Help Desk</div>
    <h2 class="title">Password Reset Request</h2>
    <p class="text">Hello,</p>
    <p class="text">We received a request to reset the password for your account (<strong>{to_email}</strong>). Use the verification code below to proceed:</p>
    
    <div class="otp-box">
      <div class="otp-label">6-Digit Verification Code</div>
      <div class="otp-code">{otp}</div>
    </div>

    <div class="passkey-box">
      <strong>Your Passkey:</strong> {passkey}
    </div>

    <a href="{reset_link}" class="btn" target="_blank">Reset Password With 1-Click Link</a>

    <p class="text" style="font-size: 13px;">This code and link will expire in <strong>15 minutes</strong>. If you did not request a password reset, no action is needed; your account remains secure.</p>
    <div class="footer">IT Help Desk System &bull; Automated Security Dispatch</div>
  </div>
</body>
</html>"""
            msg.add_alternative(html_body, subtype='html')

            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30,context=ssl.create_default_context()) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_server, smtp_port, timeout=12) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)

            print(f"✅ Real email successfully delivered to {to_email} via SMTP!")
            return True, "Email successfully sent to your registered address."
        except Exception as e:
            err_msg = str(e)
            print(f"❌ SMTP Error sending to {to_email}: {err_msg}")
            return False, f"SMTP delivery failed: {err_msg}"

    return False, "SMTP is not configured in .env."

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerform()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data.strip()

        # Extra regex sanity check
        if not re.match(EMAIL_REGEX, email):
            flash('Please enter a valid email address (e.g. user@example.com).', 'danger')
            return render_template('register.html', form=form)

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # 1. Uniqueness check for email (case-insensitive)
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            flash(f"An account with email '{email}' is already registered. Please log in instead.", 'danger')
            return render_template('register.html', form=form)

        # 2. Check if username is already taken (case-insensitive)
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = %s", (username.lower(),))
        if cursor.fetchone():
            cursor.close()
            flash(f"Username '{username}' is already taken. Please choose another one.", 'danger')
            return render_template('register.html', form=form)

        # 3. Create user
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                (username, email, password, 'student')
            )
            db.commit()
            cursor.close()
            flash('Registration successful! You may now log in to your account.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            cursor.close()
            if err.errno == 1062:
                flash(f"An account with this email is already registered.", 'danger')
            else:
                flash(f'Registration error: {err.msg}', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = loginform()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data.strip()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE LOWER(email)=%s AND password=%s', (email, password))
        user = cursor.fetchone()
        cursor.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            flash(f'Welcome back, {user[1]}!', 'success')
            if user[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please verify your credentials.', 'danger')
    return render_template('login.html', form=form)

# ==========================================
# FORGOT PASSWORD, OTP & PASSKEY RESET ROUTES
# ==========================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = forgotpasswordform()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT id, username, email FROM users WHERE LOWER(email) = %s", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            flash("No account registered with that email address. Please check and try again.", "danger")
            return render_template('forgot_password.html', form=form)

        # Generate 6-digit OTP and secure passkey
        otp = f"{secrets.randbelow(1000000):06d}"
        passkey = secrets.token_urlsafe(24)
        expires_at = datetime.now() + timedelta(minutes=15)

        # Invalidate previous unused reset requests for this user
        cursor.execute("UPDATE password_resets SET is_used = 1 WHERE user_id = %s AND is_used = 0", (user['id'],))

        # Insert new reset record
        cursor.execute("""
            INSERT INTO password_resets (user_id, email, otp, passkey, expires_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (user['id'], email, otp, passkey, expires_at))
        db.commit()
        cursor.close()

        # Send email (and log to console for development)
        sent, send_msg = send_reset_email(email, otp, passkey)

        session['reset_email'] = email

        if sent:
            flash(f"A 6-digit verification code and reset link have been sent to {email}. Please check your inbox or spam folder.", "info")
        else:
            flash(f"A verification code has been generated. (Note: Email delivery requires SMTP configured in .env).", "warning")
        return redirect(url_for('verify_otp', email=email))

    return render_template('forgot_password.html', form=form)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or session.get('reset_email')
    if not email:
        flash("Please enter your email to start the password reset process.", "warning")
        return redirect(url_for('forgot_password'))

    form = verifyotpform()

    if form.validate_on_submit():
        user_input = form.otp.data.strip()
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, user_id, email, otp, passkey, expires_at, is_used
            FROM password_resets
            WHERE LOWER(email) = %s AND (otp = %s OR passkey = %s) AND is_used = 0
            ORDER BY id DESC LIMIT 1
        """, (email.lower(), user_input, user_input))
        reset_record = cursor.fetchone()
        cursor.close()

        if not reset_record:
            flash("Invalid OTP or Passkey. Please verify and try again.", "danger")
            return render_template('verify_otp.html', form=form, email=email)

        if reset_record['expires_at'] < datetime.now():
            flash("This OTP or Passkey has expired. Please request a new one.", "danger")
            return render_template('verify_otp.html', form=form, email=email)

        # Mark verified in session
        session['reset_verified_id'] = reset_record['id']
        session['reset_user_id'] = reset_record['user_id']
        session['reset_email'] = email

        flash("Verification successful! Please create your new password.", "success")
        return redirect(url_for('reset_password'))

    return render_template('verify_otp.html', form=form, email=email)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # Check if coming via direct passkey URL link: ?passkey=...&email=...
    passkey_arg = request.args.get('passkey')
    email_arg = request.args.get('email')

    if passkey_arg and email_arg:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, user_id, email, expires_at, is_used
            FROM password_resets
            WHERE LOWER(email) = %s AND passkey = %s AND is_used = 0
            ORDER BY id DESC LIMIT 1
        """, (email_arg.lower(), passkey_arg))
        record = cursor.fetchone()
        cursor.close()

        if record and record['expires_at'] >= datetime.now():
            session['reset_verified_id'] = record['id']
            session['reset_user_id'] = record['user_id']
            session['reset_email'] = record['email']
            flash("Passkey link validated! You can set your new password below.", "success")
        else:
            flash("This passkey reset link is invalid or has expired.", "danger")
            return redirect(url_for('forgot_password'))

    # If neither passkey link nor verified OTP in session
    if 'reset_user_id' not in session or 'reset_verified_id' not in session:
        flash("Please verify your identity with an OTP or Passkey first.", "warning")
        return redirect(url_for('forgot_password'))

    form = resetpasswordform()
    if form.validate_on_submit():
        new_password = form.password.data.strip()
        confirm_password = form.confirm_password.data.strip()

        if new_password != confirm_password:
            flash("Passwords do not match. Please re-enter both carefully.", "danger")
            return render_template('reset_password.html', form=form)

        if len(new_password) < 4:
            flash("Password must be at least 4 characters long.", "danger")
            return render_template('reset_password.html', form=form)

        user_id = session['reset_user_id']
        reset_id = session['reset_verified_id']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, user_id))
        cursor.execute("UPDATE password_resets SET is_used = 1 WHERE id = %s", (reset_id,))
        db.commit()
        cursor.close()

        # Clean session
        session.pop('reset_verified_id', None)
        session.pop('reset_user_id', None)
        session.pop('reset_email', None)

        flash("Password reset successfully! You can now log in with your new password.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


@app.route('/resend-otp', methods=['GET', 'POST'])
def resend_otp():
    email = request.values.get('email') or session.get('reset_email')
    if not email:
        flash("Email is required to resend verification code.", "danger")
        return redirect(url_for('forgot_password'))

    email = email.strip().lower()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        flash("No account registered with that email address.", "danger")
        return redirect(url_for('forgot_password'))

    otp = f"{secrets.randbelow(1000000):06d}"
    passkey = secrets.token_urlsafe(24)
    expires_at = datetime.now() + timedelta(minutes=15)

    cursor.execute("UPDATE password_resets SET is_used = 1 WHERE user_id = %s AND is_used = 0", (user['id'],))
    cursor.execute("""
        INSERT INTO password_resets (user_id, email, otp, passkey, expires_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (user['id'], email, otp, passkey, expires_at))
    db.commit()
    cursor.close()

    sent, send_msg = send_reset_email(email, otp, passkey)
    session['reset_email'] = email

    if sent:
        flash(f"A new verification code and reset link have been sent to {email}. Please check your inbox or spam folder.", "info")
    else:
        flash(f"A new verification code was generated! (Note: Email delivery requires SMTP configured in .env).", "warning")
    return redirect(url_for('verify_otp', email=email))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # Open tickets
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE user_id=%s AND status='Open'", (user_id,))
    open_count = cursor.fetchone()[0]

    # In Progress tickets
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE user_id=%s AND status='In Progress'", (user_id,))
    progress_count = cursor.fetchone()[0]

    # Resolved tickets
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE user_id=%s AND status='Resolved'", (user_id,))
    resolved_count = cursor.fetchone()[0]

    # Recent tickets
    cursor.execute("""
        SELECT id, user_id, category_id, title, description, status, assigned_to, created_at
        FROM tickets
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 5
    """, (user_id,))
    tickets = cursor.fetchall()
    cursor.close()

    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session.get('role', 'student'),
        open_count=open_count,
        progress_count=progress_count,
        resolved_count=resolved_count,
        tickets=tickets
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/new-issue', methods=['GET', 'POST'])
def new_issue():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = newissue()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM categories")
    categories = cursor.fetchall()
    form.category.choices = categories

    if form.validate_on_submit():
        title = form.title.data.strip()
        category_id = form.category.data
        description = form.description.data.strip()
        user_id = session['user_id']

        valid_cat_ids = [c[0] for c in categories]
        if category_id not in valid_cat_ids:
            flash('Invalid category selected. Please choose a valid category.', 'danger')
            cursor.close()
            return render_template('new_issue.html', form=form)

        cursor.execute("""
            INSERT INTO tickets (user_id, category_id, title, description)
            VALUES (%s, %s, %s, %s)
        """, (user_id, category_id, title, description))
        db.commit()
        cursor.close()
        flash('Issue submitted successfully! Our support team will review it.', 'success')
        return redirect(url_for('dashboard'))

    cursor.close()
    return render_template('new_issue.html', form=form)

@app.route('/my_tickets')
def my_ticket():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            t.id,
            t.title,
            t.description,
            t.status,
            t.created_at,
            c.name AS category,
            a.username AS assigned_agent
        FROM tickets t
        JOIN categories c ON t.category_id = c.id
        LEFT JOIN users a ON t.assigned_to = a.id
        WHERE t.user_id = %s
        ORDER BY t.created_at DESC
    """, (user_id,))

    tickets = cursor.fetchall()
    cursor.close()

    return render_template('my_ticket.html', tickets=tickets)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    return render_template('profile.html')

# ==========================================
# ADMIN DASHBOARD & TICKET ASSIGNMENT ROUTES
# ==========================================

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # 1. Fetch KPI Statistics across the entire system
    cursor.execute("SELECT COUNT(*) AS total FROM tickets")
    total_tickets = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS open_cnt FROM tickets WHERE status='Open'")
    open_tickets = cursor.fetchone()['open_cnt']

    cursor.execute("SELECT COUNT(*) AS progress_cnt FROM tickets WHERE status='In Progress'")
    progress_tickets = cursor.fetchone()['progress_cnt']

    cursor.execute("SELECT COUNT(*) AS resolved_cnt FROM tickets WHERE status='Resolved'")
    resolved_tickets = cursor.fetchone()['resolved_cnt']

    cursor.execute("SELECT COUNT(*) AS closed_cnt FROM tickets WHERE status='Closed'")
    closed_tickets = cursor.fetchone()['closed_cnt']

    cursor.execute("SELECT COUNT(*) AS unassigned_cnt FROM tickets WHERE assigned_to IS NULL")
    unassigned_tickets = cursor.fetchone()['unassigned_cnt']

    # 2. Fetch all tickets with rich requester, category, and assigned agent information
    cursor.execute("""
        SELECT 
            t.id,
            t.user_id,
            t.category_id,
            t.title,
            t.description,
            t.status,
            t.assigned_to,
            t.created_at,
            t.updated_at,
            c.name AS category_name,
            u.username AS requester_name,
            u.email AS requester_email,
            u.role AS requester_role,
            a.username AS agent_name,
            a.email AS agent_email,
            a.role AS agent_role
        FROM tickets t
        JOIN categories c ON t.category_id = c.id
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users a ON t.assigned_to = a.id
        ORDER BY t.created_at DESC
    """)
    tickets = cursor.fetchall()

    # 3. Fetch all eligible support agents (staff and admin) with their active workloads
    cursor.execute("""
        SELECT 
            u.id, 
            u.username, 
            u.email, 
            u.role,
            COUNT(CASE WHEN t.status IN ('Open', 'In Progress') THEN 1 END) AS active_tickets
        FROM users u
        LEFT JOIN tickets t ON t.assigned_to = u.id
        WHERE u.role IN ('staff', 'admin')
        GROUP BY u.id, u.username, u.email, u.role
        ORDER BY u.role ASC, u.username ASC
    """)
    agents = cursor.fetchall()

    # 4. Fetch all categories for filter options
    cursor.execute("SELECT id, name FROM categories ORDER BY name ASC")
    categories = cursor.fetchall()

    # 5. Fetch all users to display in the Agent Management Drawer / quick role updates
    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY role ASC, username ASC")
    all_users = cursor.fetchall()

    cursor.close()

    stats = {
        'total': total_tickets,
        'open': open_tickets,
        'in_progress': progress_tickets,
        'resolved': resolved_tickets,
        'closed': closed_tickets,
        'unassigned': unassigned_tickets
    }

    return render_template(
        'admin_dashboard.html',
        username=session['username'],
        role=session['role'],
        stats=stats,
        tickets=tickets,
        agents=agents,
        categories=categories,
        all_users=all_users
    )

@app.route('/admin/assign-agent', methods=['POST'])
@admin_required
def assign_agent():
    """Assigns an agent to a specific ticket and optionally updates status and records notes"""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    data = request.get_json(silent=True) or request.form

    ticket_id = data.get('ticket_id')
    agent_id = data.get('agent_id')
    new_status = data.get('status')
    admin_note = data.get('note', '').strip()

    if not ticket_id:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Missing ticket ID'}), 400
        flash('Ticket ID is required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Normalize agent_id (if empty string or 'unassigned', set to None)
    if agent_id in ('', 'unassigned', 'None', None):
        agent_id_val = None
    else:
        try:
            agent_id_val = int(agent_id)
        except ValueError:
            agent_id_val = None

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Verify ticket exists
    cursor.execute("SELECT id, status, assigned_to FROM tickets WHERE id = %s", (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        cursor.close()
        if is_ajax:
            return jsonify({'success': False, 'message': f'Ticket #{ticket_id} not found'}), 404
        flash(f'Ticket #{ticket_id} not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    old_status = ticket['status']
    agent_name = "Unassigned"

    # Verify agent if specified
    if agent_id_val:
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (agent_id_val,))
        agent = cursor.fetchone()
        if not agent:
            cursor.close()
            if is_ajax:
                return jsonify({'success': False, 'message': 'Selected agent not found'}), 404
            flash('Selected agent not found.', 'danger')
            return redirect(url_for('admin_dashboard'))
        if agent['role'] not in ('staff', 'admin'):
            cursor.close()
            msg = f"User '{agent['username']}' is not a designated support agent (role: {agent['role']})."
            if is_ajax:
                return jsonify({'success': False, 'message': msg}), 400
            flash(msg, 'danger')
            return redirect(url_for('admin_dashboard'))
        agent_name = agent['username']

    # Validate status
    if new_status and new_status not in ['Open', 'In Progress', 'Resolved', 'Closed']:
        cursor.close()
        if is_ajax:
            return jsonify({'success': False, 'message': 'Invalid status selected'}), 400
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Auto-advance to "In Progress" if currently Open and being assigned, unless a specific status is requested
    final_status = new_status if new_status else (
        'In Progress' if (agent_id_val and old_status == 'Open') else old_status
    )

    # Update ticket
    cursor.execute("""
        UPDATE tickets 
        SET assigned_to = %s, status = %s 
        WHERE id = %s
    """, (agent_id_val, final_status, ticket_id))

    # Record status transition in ticket_history if status changed
    if old_status != final_status:
        cursor.execute("""
            INSERT INTO ticket_history (ticket_id, changed_by, old_status, new_status)
            VALUES (%s, %s, %s, %s)
        """, (ticket_id, session['user_id'], old_status, final_status))

    # Add optional comment / resolution note if provided
    if admin_note:
        cursor.execute("""
            INSERT INTO ticket_comments (ticket_id, user_id, comment)
            VALUES (%s, %s, %s)
        """, (ticket_id, session['user_id'], admin_note))

    db.commit()
    cursor.close()

    success_msg = f"Ticket #{ticket_id} assigned to {agent_name} (Status: {final_status})"
    if is_ajax:
        return jsonify({
            'success': True,
            'message': success_msg,
            'ticket_id': ticket_id,
            'agent_id': agent_id_val,
            'agent_name': agent_name,
            'status': final_status
        })

    flash(success_msg, 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update-status', methods=['POST'])
@admin_required
def update_status():
    """Quickly update ticket status directly from the dashboard"""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    data = request.get_json(silent=True) or request.form

    ticket_id = data.get('ticket_id')
    new_status = data.get('status')
    note = data.get('note', '').strip()

    if not ticket_id or new_status not in ['Open', 'In Progress', 'Resolved', 'Closed']:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Invalid status or ticket ID'}), 400
        flash('Invalid status or ticket ID.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, status FROM tickets WHERE id = %s", (ticket_id,))
    ticket = cursor.fetchone()

    if not ticket:
        cursor.close()
        if is_ajax:
            return jsonify({'success': False, 'message': 'Ticket not found'}), 404
        flash('Ticket not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    old_status = ticket['status']
    cursor.execute("UPDATE tickets SET status = %s WHERE id = %s", (new_status, ticket_id))

    if old_status != new_status:
        cursor.execute("""
            INSERT INTO ticket_history (ticket_id, changed_by, old_status, new_status)
            VALUES (%s, %s, %s, %s)
        """, (ticket_id, session['user_id'], old_status, new_status))

    if note:
        cursor.execute("""
            INSERT INTO ticket_comments (ticket_id, user_id, comment)
            VALUES (%s, %s, %s)
        """, (ticket_id, session['user_id'], note))

    db.commit()
    cursor.close()

    success_msg = f"Ticket #{ticket_id} status updated to {new_status}"
    if is_ajax:
        return jsonify({
            'success': True,
            'message': success_msg,
            'ticket_id': ticket_id,
            'status': new_status
        })

    flash(success_msg, 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/ticket-details/<int:ticket_id>')
@admin_required
def ticket_details(ticket_id):
    """Fetches full ticket details, conversation notes, and status audit trail for modal view"""
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT 
            t.id,
            t.title,
            t.description,
            t.status,
            t.assigned_to,
            t.created_at,
            t.updated_at,
            c.name AS category_name,
            u.username AS requester_name,
            u.email AS requester_email,
            a.username AS agent_name,
            a.email AS agent_email
        FROM tickets t
        JOIN categories c ON t.category_id = c.id
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users a ON t.assigned_to = a.id
        WHERE t.id = %s
    """, (ticket_id,))
    ticket = cursor.fetchone()

    if not ticket:
        cursor.close()
        return jsonify({'success': False, 'message': 'Ticket not found'}), 404

    # Format datetime strings for JSON
    ticket['created_at_fmt'] = ticket['created_at'].strftime('%b %d, %Y at %I:%M %p') if ticket['created_at'] else ''
    ticket['updated_at_fmt'] = ticket['updated_at'].strftime('%b %d, %Y at %I:%M %p') if ticket['updated_at'] else ''
    del ticket['created_at']
    del ticket['updated_at']

    # Fetch comments
    cursor.execute("""
        SELECT 
            tc.id,
            tc.comment,
            tc.created_at,
            u.username,
            u.role
        FROM ticket_comments tc
        JOIN users u ON tc.user_id = u.id
        WHERE tc.ticket_id = %s
        ORDER BY tc.created_at ASC
    """, (ticket_id,))
    comments = cursor.fetchall()
    for c in comments:
        c['created_at_fmt'] = c['created_at'].strftime('%b %d, %Y at %I:%M %p') if c['created_at'] else ''
        del c['created_at']

    # Fetch status history
    cursor.execute("""
        SELECT 
            th.id,
            th.old_status,
            th.new_status,
            th.changed_at,
            u.username AS changed_by
        FROM ticket_history th
        JOIN users u ON th.changed_by = u.id
        WHERE th.ticket_id = %s
        ORDER BY th.changed_at ASC
    """, (ticket_id,))
    history = cursor.fetchall()
    for h in history:
        h['changed_at_fmt'] = h['changed_at'].strftime('%b %d, %Y at %I:%M %p') if h['changed_at'] else ''
        del h['changed_at']

    cursor.close()

    return jsonify({
        'success': True,
        'ticket': ticket,
        'comments': comments,
        'history': history
    })

@app.route('/admin/update-user-role', methods=['POST'])
@admin_required
def update_user_role():
    """Allows admin to designate staff agents or administrators directly from the UI"""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    data = request.get_json(silent=True) or request.form

    target_user_id = data.get('user_id')
    new_role = data.get('role')

    if not target_user_id or new_role not in ['student', 'staff', 'admin']:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Invalid user ID or role'}), 400
        flash('Invalid user ID or role.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, target_user_id))
    db.commit()
    cursor.close()

    success_msg = f"User role updated to '{new_role}'"
    if is_ajax:
        return jsonify({'success': True, 'message': success_msg, 'user_id': target_user_id, 'role': new_role})

@app.route('/admin/add-agent', methods=['POST'])
@admin_required
def add_agent():
    """Allows admin to create a new support agent or admin account directly"""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    data = request.get_json(silent=True) or request.form

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    role = (data.get('role') or 'staff').strip().lower()

    if not username or not email or not password:
        msg = 'Full name, email address, and initial password are all required.'
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    if len(username) < 3 or len(username) > 50:
        msg = 'Username must be between 3 and 50 characters long.'
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    if not re.match(EMAIL_REGEX, email):
        msg = f"'{email}' is not a valid email address format (e.g. name@example.com)."
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    if len(password) < 6:
        msg = 'Agent password must be at least 6 characters long for security.'
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    if role not in ['staff', 'admin']:
        role = 'staff'

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Check if email is already registered (case-insensitive)
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
    existing = cursor.fetchone()
    if existing:
        cursor.close()
        msg = f"An account with email '{email}' is already registered in the system."
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    # Check if username is already taken (case-insensitive)
    cursor.execute("SELECT id FROM users WHERE LOWER(username) = %s", (username.lower(),))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.close()
        msg = f"Username '{username}' is already taken by another account."
        if is_ajax:
            return jsonify({'success': False, 'message': msg}), 400
        flash(msg, 'danger')
        return redirect(url_for('admin_dashboard'))

    # Insert new agent
    cursor.execute("""
        INSERT INTO users (username, email, password, role)
        VALUES (%s, %s, %s, %s)
    """, (username, email, password, role))
    new_user_id = cursor.lastrowid
    db.commit()
    cursor.close()

    success_msg = f"Support Agent '{username}' ({role.capitalize()}) added successfully!"
    if is_ajax:
        return jsonify({
            'success': True,
            'message': success_msg,
            'user': {
                'id': new_user_id,
                'username': username,
                'email': email,
                'role': role
            }
        })

    flash(success_msg, 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)