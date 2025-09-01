# Imports
import csv
import smtplib
from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TimeField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from email.mime.text import MIMEText
# Twilio SMS
from twilio.rest import Client

# App initialization
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this for production
app.config['WTF_CSRF_ENABLED'] = True

# WTForms for input validation and CSRF protection
class BookingForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email', validators=[Email(), Length(max=100)])
    woreda = SelectField('Woreda/Kebele', choices=[], validators=[DataRequired()])
    cert_type = SelectField('Certificate Type', choices=[('marital', 'Marital'), ('birth', 'Birth Certificate'), ('divorce', 'Divorce Certificate'), ('death', 'Death Certificate'), ('other', 'Other')], validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('normal', 'Normal'), ('priority', 'Elderly/Disabled')], default='normal')
    appointment_date = DateField('Appointment Date', format='%Y-%m-%d')
    phone = StringField('Phone', validators=[Length(min=10, max=15)])

class FeedbackForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired(), Length(max=100)])
    message = StringField('Message', validators=[DataRequired(), Length(max=500)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

# Admin credentials (for demo)
ADMIN_USERNAME = 'alembesh'
ADMIN_PASSWORD = 'alembesh@2876'

# Staff accounts (for demo, in-memory)


# MySQL connection details
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Alembesh@chromepay!',
    'database': 'queue_system'
}

# Twilio config (replace with your credentials)
TWILIO_ACCOUNT_SID = 'USe1455c27eea7fc1ede24fa4babd48769'
TWILIO_AUTH_TOKEN = 'f0ac2b6239051ff33873df4db5a35f08'
TWILIO_PHONE_NUMBER = '+251928765032'

def get_db():
    return mysql.connector.connect(**db_config)

def send_confirmation_email(to_email, name, queue_number, woreda):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'alembeshgetaneh@gmail.com'  # Replace with your email
    sender_password = 'sychufmyeezqjwxe'  # Replace with your app password
    subject = 'Queue Booking Confirmation'
    body = f"Hello {name},\n\nYour booking is confirmed. Your queue number is {queue_number}.\n\nPlease collect your certificate at {woreda} office on your appointment day.\n\nThank you!"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print('Email error:', e)

def send_confirmation_sms(to_phone, name, queue_number, woreda):
    body = f"Hello {name}, your booking is confirmed. Your queue number is {queue_number}. Please collect your certificate at {woreda} office on your appointment day. Thank you!"
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=body,
            from_=TWILIO_PHONE_NUMBER,
            to=to_phone
        )
        print('SMS sent:', message.sid)
    except Exception as e:
        print('SMS error:', e)

# ROUTES

# Staff credential update
class UpdateCredentialsForm(FlaskForm):
    username = StringField('New Username', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[DataRequired()])

@app.route('/staff/update_credentials', methods=['GET', 'POST'])
def staff_update_credentials():
    if not session.get('staff_logged_in'):
        return redirect(url_for('staff_login'))
    form = UpdateCredentialsForm()
    message = None
    errors = []
    if form.validate_on_submit():
        new_username = form.username.data
        new_password = form.password.data
        db = get_db()
        cursor = db.cursor()
        # Check if new username is taken
        cursor.execute('SELECT id FROM staff WHERE username=%s', (new_username,))
        if cursor.fetchone() and new_username != session['staff_logged_in']:
            errors.append('Username already taken.')
        if len(new_password) < 8 or not any(c.isupper() for c in new_password) or not any(c.islower() for c in new_password) or not any(c.isdigit() for c in new_password):
            errors.append('Password must be at least 8 characters and include upper, lower, and number.')
        if not errors:
            password_hash = generate_password_hash(new_password)
            cursor.execute('UPDATE staff SET username=%s, password_hash=%s WHERE username=%s', (new_username, password_hash, session['staff_logged_in']))
            db.commit()
            session['staff_logged_in'] = new_username
            message = 'Credentials updated.'
        cursor.close()
        db.close()
    return render_template('update_credentials.html', form=form, message=message, errors=errors)

# Staff profile/dashboard with personal stats
@app.route('/staff/profile')
def staff_profile():
    if not session.get('staff_logged_in'):
        return redirect(url_for('staff_login'))
    db = get_db()
    cursor = db.cursor()
    staff_username = session['staff_logged_in']
    # Get login history (for demo, just last login time)
    # You can extend this to a login_log table for full history
    # Get number of citizens served
    cursor.execute('SELECT COUNT(*) FROM service_log WHERE staff_username=%s', (staff_username,))
    served_count = cursor.fetchone()[0]
    # Get list of citizens served
    cursor.execute('SELECT name, cert_type, priority, served_at FROM service_log WHERE staff_username=%s ORDER BY served_at DESC LIMIT 20', (staff_username,))
    logs = [ {'name': row[0], 'cert_type': row[1], 'priority': row[2], 'served_at': row[3]} for row in cursor.fetchall() ]
    cursor.close()
    db.close()
    return render_template('staff_profile.html', staff=staff_username, served_count=served_count, logs=logs)

@app.route('/', methods=['GET', 'POST'])
def home():
    queue_number = None
    feedback_sent = False
    errors = []
    db = get_db()
    cursor = db.cursor()
    # Ensure locations table exists
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS locations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) UNIQUE
        )''')
    except:
        pass
    # Load locations for dropdown
    cursor.execute('SELECT name FROM locations ORDER BY name')
    location_choices = [(row[0], row[0]) for row in cursor.fetchall()]
    cursor.close()
    db.close()
    form = BookingForm()
    form.woreda.choices = location_choices if location_choices else [('Woreda 1', 'Woreda 1')]
    feedback_form = FeedbackForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        woreda = form.woreda.data
        cert_type = form.cert_type.data
        priority = form.priority.data
        appointment_date = form.appointment_date.data
        phone = form.phone.data
        # Basic validation
        if not name:
            errors.append('Name is required.')
        if email and '@' not in email:
            errors.append('Email address is invalid.')
        if not cert_type:
            errors.append('Certificate type is required.')
        if phone and (len(phone) < 10 or len(phone) > 15):
            errors.append('Phone number must be between 10 and 15 digits.')
        if not errors:
            db = get_db()
            cursor = db.cursor()
            # Try to add columns if not exists
            try:
                cursor.execute('ALTER TABLE queue ADD COLUMN woreda VARCHAR(50)')
            except:
                pass
            try:
                cursor.execute('ALTER TABLE queue ADD COLUMN priority VARCHAR(10) DEFAULT "normal"')
            except:
                pass
            try:
                cursor.execute('ALTER TABLE queue ADD COLUMN email VARCHAR(100)')
            except:
                pass
            try:
                cursor.execute('ALTER TABLE queue ADD COLUMN appointment_date DATE')
            except:
                pass
            try:
                cursor.execute('INSERT INTO queue (name, email, woreda, cert_type, priority, appointment_date) VALUES (%s, %s, %s, %s, %s, %s)', (name, email, woreda, cert_type, priority, appointment_date))
            except:
                cursor.execute('INSERT INTO queue (name, woreda, cert_type, priority) VALUES (%s, %s, %s, %s)', (name, woreda, cert_type, priority))
            db.commit()
            # Estimated wait time: count people ahead with same date
            if appointment_date:
                cursor.execute('SELECT COUNT(*) FROM queue WHERE appointment_date=%s', (appointment_date,))
                queue_number = cursor.fetchone()[0]
            else:
                cursor.execute('SELECT COUNT(*) FROM queue')
                queue_number = cursor.fetchone()[0]
            cursor.close()
            db.close()
            # Send confirmation email
            if email:
                send_confirmation_email(email, name, queue_number, woreda)
            # Send SMS if phone number provided
            if phone:
                send_confirmation_sms(phone, name, queue_number, woreda)
    elif feedback_form.validate_on_submit():
        name = feedback_form.name.data
        message = feedback_form.message.data
        db = get_db()
        cursor = db.cursor()
        # Ensure feedback table exists with required columns
        try:
            cursor.execute('''CREATE TABLE IF NOT EXISTS feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100),
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT FALSE
            )''')
        except:
            pass
        cursor.execute('INSERT INTO feedback (name, message) VALUES (%s, %s)', (name, message))
        db.commit()
        cursor.close()
        db.close()
        feedback_sent = True
    return render_template('index.html', queue_number=queue_number, feedback_sent=feedback_sent, form=form, feedback_form=feedback_form, errors=errors)
# Admin manage locations (Woreda/Kebele)
class LocationForm(FlaskForm):
    name = StringField('Location Name', validators=[DataRequired(), Length(max=100)])

@app.route('/admin/locations', methods=['GET', 'POST'])
def admin_locations():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    form = LocationForm()
    message = None
    errors = []
    db = get_db()
    cursor = db.cursor()
    # Ensure locations table exists
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS locations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) UNIQUE
        )''')
    except:
        pass
    if form.validate_on_submit():
        name = form.name.data.strip()
        if not name:
            errors.append('Location name is required.')
        else:
            cursor.execute('SELECT id FROM locations WHERE name=%s', (name,))
            if cursor.fetchone():
                errors.append('Location already exists.')
        if not errors:
            cursor.execute('INSERT INTO locations (name) VALUES (%s)', (name,))
            db.commit()
            message = f'Location "{name}" added.'
    # Get all locations
    cursor.execute('SELECT id, name FROM locations ORDER BY name')
    locations = [ {'id': row[0], 'name': row[1]} for row in cursor.fetchall() ]
    cursor.close()
    db.close()
    return render_template('admin_locations.html', form=form, message=message, errors=errors, locations=locations)

# Admin delete location
@app.route('/admin/delete_location', methods=['POST'])
def delete_location():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    location_id = request.form.get('location_id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM locations WHERE id=%s', (location_id,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for('admin_locations'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    errors = []
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if username != ADMIN_USERNAME:
            errors.append('Admin username is incorrect.')
        if password != ADMIN_PASSWORD:
            errors.append('Admin password is incorrect.')
        if not errors:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html', errors=errors, form=form)

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT name, cert_type, priority FROM queue ORDER BY id')
    queue = [ {'name': row[0], 'cert_type': row[1], 'priority': row[2] if len(row) > 2 else 'normal'} for row in cursor.fetchall() ]
    cursor.execute('SELECT name, cert_type, priority, served_at FROM service_log ORDER BY served_at DESC LIMIT 20')
    logs = [ {'name': row[0], 'cert_type': row[1], 'priority': row[2], 'served_at': row[3]} for row in cursor.fetchall() ]
    # Get staff list for removal
    cursor.execute('SELECT username FROM staff')
    staff_list = [row[0] for row in cursor.fetchall()]
    cursor.close()
    db.close()
    return render_template('admin_dashboard.html', queue=queue, logs=logs, staff_list=staff_list)

# Admin credential update
class AdminUpdateForm(FlaskForm):
    username = StringField('New Admin Username', validators=[DataRequired()])
    password = PasswordField('New Admin Password', validators=[DataRequired()])

@app.route('/admin/update_credentials', methods=['GET', 'POST'])
def admin_update_credentials():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    form = AdminUpdateForm()
    message = None
    global ADMIN_USERNAME, ADMIN_PASSWORD
    if form.validate_on_submit():
        ADMIN_USERNAME = form.username.data
        ADMIN_PASSWORD = form.password.data
        message = 'Admin credentials updated.'
    return render_template('admin_update_credentials.html', form=form, message=message)

# Admin remove staff
@app.route('/admin/remove_staff', methods=['POST'])
def remove_staff():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    username = request.form.get('username')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM staff WHERE username=%s', (username,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export_logs')
def export_logs():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT name, cert_type, priority, served_at FROM service_log ORDER BY served_at DESC')
    logs = cursor.fetchall()
    cursor.close()
    db.close()
    def generate():
        data = [['Name', 'Certificate Type', 'Priority', 'Served At']]
        for row in logs:
            data.append(list(row))
        output = []
        for line in data:
            output.append(','.join([str(x) for x in line]))
        return '\n'.join(output)
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=service_logs.csv'})

@app.route('/admin/reset_queue', methods=['POST'])
def reset_queue():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM queue')
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/add_staff', methods=['GET', 'POST'])
def add_staff():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    message = None
    errors = []
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()
        # Create staff table if not exists
        try:
            cursor.execute('''CREATE TABLE IF NOT EXISTS staff (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE,
                password_hash VARCHAR(255)
            )''')
        except:
            pass
        cursor.execute('SELECT id FROM staff WHERE username=%s', (username,))
        if cursor.fetchone():
            errors.append('Staff username already exists.')
        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            errors.append('Password must be at least 8 characters and include upper, lower, and number.')
        if not errors:
            password_hash = generate_password_hash(password)
            cursor.execute('INSERT INTO staff (username, password_hash) VALUES (%s, %s)', (username, password_hash))
            db.commit()
            message = f'Staff {username} added.'
        cursor.close()
        db.close()
    return render_template('add_staff.html', message=message, errors=errors, form=form)

@app.route('/staff/login', methods=['GET', 'POST'])
def staff_login():
    errors = []
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()
        # Ensure staff table exists
        try:
            cursor.execute('''CREATE TABLE IF NOT EXISTS staff (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE,
                password_hash VARCHAR(255)
            )''')
        except:
            pass
        cursor.execute('SELECT password_hash FROM staff WHERE username=%s', (username,))
        row = cursor.fetchone()
        cursor.close()
        db.close()
        if not row:
            errors.append('Username does not exist.')
        elif not check_password_hash(row[0], password):
            errors.append('Incorrect password.')
        else:
            session['staff_logged_in'] = username
            return redirect(url_for('staff_dashboard'))
    return render_template('staff_login.html', errors=errors, form=form)

@app.route('/staff/dashboard')
def staff_dashboard():
    if not session.get('staff_logged_in'):
        return redirect(url_for('staff_login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, name, cert_type, priority, appointment_date, appointment_time FROM queue ORDER BY id')
    queue = [ {'id': row[0], 'name': row[1], 'cert_type': row[2], 'priority': row[3] if len(row) > 3 else 'normal', 'appointment_date': str(row[4]) if row[4] else '', 'appointment_time': str(row[5]) if row[5] else ''} for row in cursor.fetchall() ]
    cursor.close()
    db.close()
    # Dashboard summary stats
    total_queue = len(queue)
    elderly_count = sum(1 for q in queue if q['priority'] == 'priority')
    normal_count = total_queue - elderly_count
    if request.args.get('ajax') == '1':
        from flask import jsonify
        return jsonify({
            'queue': queue,
            'total_queue': total_queue,
            'elderly_count': elderly_count,
            'normal_count': normal_count
        })
    return render_template('staff_dashboard.html', queue=queue, staff=session['staff_logged_in'], total_queue=total_queue, elderly_count=elderly_count, normal_count=normal_count)

@app.route('/staff/logout')
def staff_logout():
    session.pop('staff_logged_in', None)
    return redirect(url_for('staff_login'))

@app.route('/staff', methods=['GET', 'POST'])
def staff():
    if not session.get('staff_logged_in'):
        return redirect(url_for('staff_login'))
    called_person = None
    db = get_db()
    cursor = db.cursor()
    # Ensure 'on_hold' and priority columns exist and have correct length
    try:
        cursor.execute('ALTER TABLE queue ADD COLUMN on_hold BOOLEAN DEFAULT FALSE')
    except:
        pass
    try:
        cursor.execute('ALTER TABLE queue MODIFY COLUMN priority VARCHAR(20) DEFAULT "normal"')
    except:
        pass
    if request.method == 'POST':
        # Staff actions: Skip/Hold
        if 'skip_id' in request.form:
            skip_id = request.form.get('skip_id')
            # Move skipped person to end of queue
            cursor.execute('SELECT * FROM queue WHERE id=%s', (skip_id,))
            skipped = cursor.fetchone()
            if skipped:
                cursor.execute('DELETE FROM queue WHERE id=%s', (skip_id,))
                cursor.execute('INSERT INTO queue (name, email, cert_type, priority, appointment_date, appointment_time, on_hold) VALUES (%s, %s, %s, %s, %s, %s, %s)', (skipped[1], skipped[2], skipped[3], skipped[4], skipped[5], skipped[6], skipped[7] if len(skipped) > 7 else False))
                db.commit()
        elif 'hold_id' in request.form:
            hold_id = request.form.get('hold_id')
            cursor.execute('UPDATE queue SET on_hold=TRUE WHERE id=%s', (hold_id,))
            db.commit()
        else:
            # Prioritize elderly/disabled
            cursor.execute('SELECT id, name, cert_type, priority FROM queue WHERE priority = "priority" AND (on_hold IS NULL OR on_hold=FALSE) ORDER BY id LIMIT 1')
            person = cursor.fetchone()
            if not person:
                cursor.execute('SELECT id, name, cert_type, priority FROM queue WHERE (on_hold IS NULL OR on_hold=FALSE) ORDER BY id LIMIT 1')
                person = cursor.fetchone()
            if person:
                called_person = {'name': person[1], 'cert_type': person[2], 'priority': person[3] if len(person) > 3 else 'normal'}
                cursor.execute('DELETE FROM queue WHERE id = %s', (person[0],))
                # Log service
                try:
                    cursor.execute('''CREATE TABLE IF NOT EXISTS service_log (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(100),
                        cert_type VARCHAR(20),
                        priority VARCHAR(10),
                        served_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        staff_username VARCHAR(100)
                    )''')
                except:
                    pass
                cursor.execute('INSERT INTO service_log (name, cert_type, priority, staff_username) VALUES (%s, %s, %s, %s)', (person[1], person[2], person[3] if len(person) > 3 else 'normal', session['staff_logged_in']))
                db.commit()
    cursor.execute('SELECT id, name, cert_type, priority, appointment_date, appointment_time FROM queue ORDER BY id')
    queue = [ {'id': row[0], 'name': row[1], 'cert_type': row[2], 'priority': row[3] if len(row) > 3 else 'normal', 'appointment_date': str(row[4]) if row[4] else '', 'appointment_time': str(row[5]) if row[5] else ''} for row in cursor.fetchall() ]
    # Get feedbacks
    # Get feedbacks
    # Add resolved column if not exists
    try:
        cursor.execute('ALTER TABLE feedback ADD COLUMN resolved BOOLEAN DEFAULT FALSE')
    except:
        pass
    if request.method == 'POST' and 'resolve_feedback' in request.form:
        feedback_id = request.form.get('resolve_feedback')
        cursor.execute('UPDATE feedback SET resolved=TRUE WHERE id=%s', (feedback_id,))
        db.commit()
    cursor.execute('SELECT id, name, message, created_at, resolved FROM feedback ORDER BY created_at DESC LIMIT 10')
    feedbacks = [ {'id': row[0], 'name': row[1], 'message': row[2], 'created_at': row[3], 'resolved': row[4]} for row in cursor.fetchall() ]
    # Get service logs
    try:
        cursor.execute('SELECT name, cert_type, priority, served_at FROM service_log ORDER BY served_at DESC LIMIT 10')
        logs = [ {'name': row[0], 'cert_type': row[1], 'priority': row[2], 'served_at': row[3]} for row in cursor.fetchall() ]
    except:
        logs = []
    cursor.close()
    db.close()
    if request.args.get('ajax') == '1':
        from flask import jsonify
        return jsonify({
            'queue': queue
        })
    return render_template('staff.html', queue=queue, called_person=called_person, feedbacks=feedbacks, logs=logs)

@app.route('/display')
def display():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT name, cert_type, priority FROM queue ORDER BY id LIMIT 1')
    person = cursor.fetchone()
    cursor.execute('SELECT COUNT(*) FROM queue')
    queue_count = cursor.fetchone()[0]
    cursor.close()
    db.close()
    return render_template('display.html', person=person, queue_count=queue_count)

# Contact, Help, Privacy Terms routes
@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/help')
def help():
    return render_template('help.html')


@app.route('/terms')
def terms():
    return render_template('terms.html')
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('ssl/cert.pem', 'ssl/key.pem'))
