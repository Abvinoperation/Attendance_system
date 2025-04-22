import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bcrypt
from datetime import datetime, timedelta, date
import csv
from io import StringIO
from io import BytesIO
from decimal import Decimal

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'attendance_system'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['MYSQL_CONNECT_TIMEOUT'] = 10

mysql = MySQL(app)

# File upload configuration
UPLOAD_FOLDER = 'static/uploads/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper functions
def get_db_connection():
    return mysql.connection.cursor()

def get_current_datetime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def calculate_work_hours(check_in, check_out):
    try:
        if isinstance(check_in, str):
            check_in = datetime.strptime(check_in, '%Y-%m-%d %H:%M:%S')
        if isinstance(check_out, str):
            check_out = datetime.strptime(check_out, '%Y-%m-%d %H:%M:%S')
        if check_in and check_out:
            delta = check_out - check_in
            return round(delta.total_seconds() / 3600, 2)
        return 0
    except Exception as e:
        print(f"Error calculating work hours: {str(e)}")
        return 0

def is_admin_logged_in():
    return 'admin_id' in session

def is_employee_logged_in():
    return 'emp_id' in session

def get_employee_details(emp_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT e.*, d.dept_name, des.desig_name 
        FROM employee e 
        LEFT JOIN department d ON e.dept_id = d.dept_id 
        LEFT JOIN designation des ON e.desig_id = des.desig_id 
        WHERE e.emp_id = %s
    """, (emp_id,))
    employee = cur.fetchone()
    cur.close()
    return employee

def get_admin_details(admin_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cur.fetchone()
    cur.close()
    return admin


def calculate_leave_days(start_date, end_date, leave_duration):
    """Calculate leave days considering half-day options"""
    if leave_duration == 'full_day':
        return (end_date - start_date).days + 1
    elif leave_duration in ['first_half', 'second_half']:
        # For half-day, count as 0.5 days per day in the range
        return ((end_date - start_date).days + 1) * 0.5
    else:
        return 0
 
def validate_leave_dates(start_date, end_date, leave_duration):
    """Validate leave dates based on duration"""
    if leave_duration == 'full_day':
        return start_date <= end_date
    elif leave_duration in ['first_half', 'second_half']:
        # For half-day, start and end dates must be the same
        return start_date == end_date
    return False

# Routes
@app.route('/')
def index():
    if is_admin_logged_in():
        return redirect(url_for('admin_dashboard'))
    elif is_employee_logged_in():
        return redirect(url_for('employee_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        role = request.form['role']
        
        if role == 'admin':
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM admin WHERE username = %s", (username,))
            admin = cur.fetchone()
            cur.close()
            
            if admin and bcrypt.checkpw(password, admin['password_hash'].encode('utf-8')):
                session['admin_id'] = admin['admin_id']
                session['username'] = admin['username']
                session['role'] = 'admin'
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        else:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM employee WHERE work_email = %s AND status = 'active'", (username,))
            employee = cur.fetchone()
            cur.close()
            
            if employee and bcrypt.checkpw(password, employee['password_hash'].encode('utf-8')):
                session['emp_id'] = employee['emp_id']
                session['username'] = employee['work_email']
                session['role'] = 'employee'
                flash('Login successful!', 'success')
                return redirect(url_for('employee_dashboard'))
            else:
                flash('Invalid username or password or account is inactive', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    
    # Get total employees
    cur.execute("SELECT COUNT(*) as total_employees FROM employee")
    total_employees = cur.fetchone()['total_employees']
    
    # Get active employees
    cur.execute("SELECT COUNT(*) as active_employees FROM employee WHERE status = 'active'")
    active_employees = cur.fetchone()['active_employees']
    
    # Get pending leave requests
    cur.execute("SELECT COUNT(*) as pending_leaves FROM leave_application WHERE status = 'pending'")
    pending_leaves = cur.fetchone()['pending_leaves']
    
    # Get today's attendance
    today = date.today().strftime('%Y-%m-%d')
    cur.execute("""
        SELECT COUNT(*) as today_present 
        FROM attendance 
        WHERE DATE(check_in) = %s AND status = 'present'
    """, (today,))
    today_present = cur.fetchone()['today_present']
    
    # Get recent leave applications
    cur.execute("""
        SELECT la.*, e.first_name, e.last_name, lt.leave_name 
        FROM leave_application la 
        JOIN employee e ON la.emp_id = e.emp_id 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE la.status = 'pending' 
        ORDER BY la.applied_on DESC 
        LIMIT 5
    """)
    recent_leaves = cur.fetchall()
    
    cur.close()
    
    return render_template('admin_dashboard.html', 
                         total_employees=total_employees,
                         active_employees=active_employees,
                         pending_leaves=pending_leaves,
                         today_present=today_present,
                         recent_leaves=recent_leaves)

# Employee Management
@app.route('/admin/employees')
def manage_employees():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT e.*, d.dept_name, des.desig_name 
        FROM employee e 
        LEFT JOIN department d ON e.dept_id = d.dept_id 
        LEFT JOIN designation des ON e.desig_id = des.desig_id 
        ORDER BY e.status, e.first_name
    """)
    employees = cur.fetchall()
    
    cur.execute("SELECT * FROM department")
    departments = cur.fetchall()
    
    cur.execute("SELECT * FROM designation")
    designations = cur.fetchall()
    
    cur.close()
    
    return render_template('manage_employees.html', 
                         employees=employees,
                         departments=departments,
                         designations=designations)


# Add this route to app3.py (around the other admin routes)

@app.route('/admin/employee/leave_balance/<int:emp_id>')
def view_employee_leave_balance(emp_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    # Get employee details
    cur.execute("""
        SELECT e.*, d.dept_name, des.desig_name 
        FROM employee e 
        LEFT JOIN department d ON e.dept_id = d.dept_id 
        LEFT JOIN designation des ON e.desig_id = des.desig_id 
        WHERE e.emp_id = %s
    """, (emp_id,))
    employee = cur.fetchone()
    if not employee:
        flash('Employee not found', 'danger')
        return redirect(url_for('manage_employees'))
    # Get leave balance with proper join to leave_type
    cur.execute("""
        SELECT lb.*, lt.leave_name, lt.max_days, lt.description 
        FROM leave_balance lb 
        JOIN leave_type lt ON lb.leave_type_id = lt.leave_type_id 
        WHERE lb.emp_id = %s
        ORDER BY lt.leave_name
    """, (emp_id,))
    leave_balances = cur.fetchall()
    cur.close()
    return render_template('admin_employee_leave_balance.html', 
                         employee=employee,
                         leave_balances=leave_balances)
 # Add this route to app3.py

@app.route('/admin/employee/adjust_leave_balance/<int:emp_id>', methods=['POST'])
def adjust_leave_balance(emp_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    leave_type_id = request.form['leave_type_id']
    adjustment_type = request.form['adjustment_type']
    days = request.form['days']  # Keep as string initially
    reason = request.form['reason']
    admin_id = session['admin_id']
    cur = mysql.connection.cursor()
    try:
        # Convert days to Decimal for precise arithmetic
        try:
            days = Decimal(days)
            if days <= 0:
                flash('Days must be a positive number', 'danger')
                return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        except:
            flash('Invalid days value', 'danger')
            return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        # Get current balance and max days from leave_type
        cur.execute("""
            SELECT lb.remaining_days, lt.max_days 
            FROM leave_balance lb
            JOIN leave_type lt ON lb.leave_type_id = lt.leave_type_id
            WHERE lb.emp_id = %s AND lb.leave_type_id = %s
        """, (emp_id, leave_type_id))
        balance = cur.fetchone()
        if not balance:
            flash('Leave balance not found', 'danger')
            return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        # Convert database values to Decimal
        current_balance = Decimal(str(balance['remaining_days']))
        max_days = Decimal(str(balance['max_days']))
        # Calculate new balance based on adjustment type
        if adjustment_type == 'add':
            new_balance = current_balance + days
        elif adjustment_type == 'subtract':
            new_balance = current_balance - days
            if new_balance < 0:
                flash('Cannot have negative leave balance', 'danger')
                return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        elif adjustment_type == 'set':
            new_balance = days
            if new_balance > max_days:
                flash(f'Cannot set balance higher than max days ({max_days})', 'danger')
                return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        else:
            flash('Invalid adjustment type', 'danger')
            return redirect(url_for('view_employee_leave_balance', emp_id=emp_id))
        # Update balance (convert back to float for MySQL)
        cur.execute("""
            UPDATE leave_balance 
            SET remaining_days = %s 
            WHERE emp_id = %s AND leave_type_id = %s
        """, (float(new_balance), emp_id, leave_type_id))
        # Record adjustment in audit log
        cur.execute("""
            INSERT INTO leave_balance_adjustment 
            (emp_id, leave_type_id, admin_id, adjustment_type, days, reason, new_balance) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            emp_id, 
            leave_type_id, 
            admin_id, 
            adjustment_type, 
            float(days), 
            reason, 
            float(new_balance)
        ))
        mysql.connection.commit()
        flash('Leave balance updated successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating leave balance: {str(e)}', 'danger')
    finally:
        cur.close()
    return redirect(url_for('view_employee_leave_balance', emp_id=emp_id)) 

@app.route('/admin/employee/add', methods=['GET', 'POST'])
def add_employee():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get form data
        employee_id = request.form['employee_id']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        work_email = request.form['work_email']
        personal_email = request.form['personal_email']
        phone = request.form['phone']
        dob = request.form['dob']
        join_date = request.form['join_date']
        end_date = request.form['end_date'] if request.form['end_date'] else None
        dept_id = request.form['dept_id']
        desig_id = request.form['desig_id']
        password = request.form['password']
        
        # Validate password length
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('add_employee'))
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Handle file upload
        profile_pic = None
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{employee_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
        
        # Insert into database
        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO employee 
                (employee_id, first_name, last_name, work_email, personal_email, phone, 
                 dob, join_date, end_date, dept_id, desig_id, password_hash, profile_pic) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (employee_id, first_name, last_name, work_email, personal_email, phone, 
                  dob, join_date, end_date, dept_id, desig_id, hashed_password, profile_pic))
            
            # Initialize leave balances
            emp_id = cur.lastrowid
            cur.execute("SELECT leave_type_id FROM leave_type")
            leave_types = cur.fetchall()
            for lt in leave_types:
                cur.execute("""
                    INSERT INTO leave_balance (emp_id, leave_type_id, remaining_days)
                    VALUES (%s, %s, (SELECT max_days FROM leave_type WHERE leave_type_id = %s))
                """, (emp_id, lt['leave_type_id'], lt['leave_type_id']))
            
            mysql.connection.commit()
            flash('Employee added successfully!', 'success')
            return redirect(url_for('manage_employees'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error adding employee: {str(e)}', 'danger')
        finally:
            cur.close()
    
    # GET request - show form
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM department")
    departments = cur.fetchall()
    
    cur.execute("SELECT * FROM designation")
    designations = cur.fetchall()
    
    cur.close()
    
    return render_template('add_employee.html', 
                         departments=departments,
                         designations=designations)

@app.route('/admin/employee/edit/<int:emp_id>', methods=['GET', 'POST'])
def edit_employee(emp_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        # Get form data
        employee_id = request.form['employee_id']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        work_email = request.form['work_email']
        personal_email = request.form['personal_email']
        phone = request.form['phone']
        dob = request.form['dob']
        join_date = request.form['join_date']
        end_date = request.form['end_date'] if request.form['end_date'] else None
        dept_id = request.form['dept_id']
        desig_id = request.form['desig_id']
        status = request.form['status']
        
        # Handle file upload
        profile_pic = None
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{employee_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
        
        # Update database
        try:
            if profile_pic:
                cur.execute("""
                    UPDATE employee 
                    SET employee_id = %s, first_name = %s, last_name = %s, 
                        work_email = %s, personal_email = %s, phone = %s, 
                        dob = %s, join_date = %s, end_date = %s, 
                        dept_id = %s, desig_id = %s, status = %s, profile_pic = %s
                    WHERE emp_id = %s
                """, (employee_id, first_name, last_name, work_email, personal_email, phone, 
                      dob, join_date, end_date, dept_id, desig_id, status, profile_pic, emp_id))
            else:
                cur.execute("""
                    UPDATE employee 
                    SET employee_id = %s, first_name = %s, last_name = %s, 
                        work_email = %s, personal_email = %s, phone = %s, 
                        dob = %s, join_date = %s, end_date = %s, 
                        dept_id = %s, desig_id = %s, status = %s
                    WHERE emp_id = %s
                """, (employee_id, first_name, last_name, work_email, personal_email, phone, 
                      dob, join_date, end_date, dept_id, desig_id, status, emp_id))
            
            # Handle password reset if provided
            new_password = request.form.get('new_password')
            if new_password and len(new_password) >= 8:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cur.execute("""
                    UPDATE employee 
                    SET password_hash = %s 
                    WHERE emp_id = %s
                """, (hashed_password, emp_id))
            
            mysql.connection.commit()
            flash('Employee updated successfully!', 'success')
            return redirect(url_for('manage_employees'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating employee: {str(e)}', 'danger')
        finally:
            cur.close()
    
    # GET request - show form with current data
    cur.execute("""
        SELECT * FROM employee 
        WHERE emp_id = %s
    """, (emp_id,))
    employee = cur.fetchone()
    
    cur.execute("SELECT * FROM department")
    departments = cur.fetchall()
    
    cur.execute("SELECT * FROM designation")
    designations = cur.fetchall()
    
    cur.close()
    
    if not employee:
        flash('Employee not found', 'danger')
        return redirect(url_for('manage_employees'))
    
    return render_template('edit_employee.html', 
                         employee=employee,
                         departments=departments,
                         designations=designations)

@app.route('/admin/employee/delete/<int:emp_id>', methods=['POST'])
def delete_employee(emp_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    try:
        # Delete all related records first
        cur.execute("DELETE FROM leave_balance WHERE emp_id = %s", (emp_id,))
        cur.execute("DELETE FROM leave_application WHERE emp_id = %s", (emp_id,))
        cur.execute("DELETE FROM attendance WHERE emp_id = %s", (emp_id,))
        
        # Then delete the employee
        cur.execute("DELETE FROM employee WHERE emp_id = %s", (emp_id,))
        mysql.connection.commit()
        flash('Employee deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting employee: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_employees'))

@app.route('/admin/employee/reset_password/<int:emp_id>', methods=['POST'])
def reset_employee_password(emp_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    new_password = request.form['new_password']
    confirm_password = request.form.get('confirm_password', '')
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long', 'danger')
        return redirect(url_for('edit_employee', emp_id=emp_id))

    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('edit_employee', emp_id=emp_id))
    
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            UPDATE employee 
            SET password_hash = %s 
            WHERE emp_id = %s
        """, (hashed_password, emp_id))
        mysql.connection.commit()
        flash('Password reset successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error resetting password: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('edit_employee', emp_id=emp_id))

# Department Management
@app.route('/admin/departments')
def manage_departments():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM department ORDER BY dept_name")
    departments = cur.fetchall()
    cur.close()
    
    return render_template('manage_departments.html', departments=departments)

@app.route('/admin/department/add', methods=['POST'])
def add_department():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    dept_name = request.form['dept_name']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO department (dept_name, description) 
            VALUES (%s, %s)
        """, (dept_name, description))
        mysql.connection.commit()
        flash('Department added successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error adding department: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_departments'))

@app.route('/admin/department/edit/<int:dept_id>', methods=['POST'])
def edit_department(dept_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    dept_name = request.form['dept_name']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            UPDATE department 
            SET dept_name = %s, description = %s 
            WHERE dept_id = %s
        """, (dept_name, description, dept_id))
        mysql.connection.commit()
        flash('Department updated successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating department: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_departments'))

@app.route('/admin/department/delete/<int:dept_id>', methods=['POST'])
def delete_department(dept_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    try:
        # Check if department has employees
        cur.execute("SELECT COUNT(*) as emp_count FROM employee WHERE dept_id = %s", (dept_id,))
        result = cur.fetchone()
        
        if result['emp_count'] > 0:
            flash('Cannot delete department with assigned employees', 'danger')
            return redirect(url_for('manage_departments'))
        
        cur.execute("DELETE FROM department WHERE dept_id = %s", (dept_id,))
        mysql.connection.commit()
        flash('Department deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting department: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_departments'))

# Designation Management
@app.route('/admin/designations')
def manage_designations():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM designation ORDER BY desig_name")
    designations = cur.fetchall()
    cur.close()
    
    return render_template('manage_designations.html', designations=designations)

@app.route('/admin/designation/add', methods=['POST'])
def add_designation():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    desig_name = request.form['desig_name']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO designation (desig_name, description) 
            VALUES (%s, %s)
        """, (desig_name, description))
        mysql.connection.commit()
        flash('Designation added successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error adding designation: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_designations'))

@app.route('/admin/designation/edit/<int:desig_id>', methods=['POST'])
def edit_designation(desig_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    desig_name = request.form['desig_name']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            UPDATE designation 
            SET desig_name = %s, description = %s 
            WHERE desig_id = %s
        """, (desig_name, description, desig_id))
        mysql.connection.commit()
        flash('Designation updated successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating designation: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_designations'))

@app.route('/admin/designation/delete/<int:desig_id>', methods=['POST'])
def delete_designation(desig_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    try:
        # Check if designation has employees
        cur.execute("SELECT COUNT(*) as emp_count FROM employee WHERE desig_id = %s", (desig_id,))
        result = cur.fetchone()
        
        if result['emp_count'] > 0:
            flash('Cannot delete designation with assigned employees', 'danger')
            return redirect(url_for('manage_designations'))
        
        cur.execute("DELETE FROM designation WHERE desig_id = %s", (desig_id,))
        mysql.connection.commit()
        flash('Designation deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting designation: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_designations'))

# Leave Type Management
@app.route('/admin/leave_types')
def manage_leave_types():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM leave_type ORDER BY leave_name")
    leave_types = cur.fetchall()
    cur.close()
    
    return render_template('manage_leave_types.html', leave_types=leave_types)

@app.route('/admin/leave_type/add', methods=['POST'])
def add_leave_type():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    leave_name = request.form['leave_name']
    description = request.form['description']
    max_days = request.form['max_days']
    half_day_allowed = 1 if request.form.get('half_day_allowed') else 0
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO leave_type (leave_name, description, max_days,half_day_allowed) 
            VALUES (%s, %s, %s,%s)
        """, (leave_name, description, max_days,half_day_allowed))

        # Get all active employees
        cur.execute("SELECT emp_id FROM employee WHERE status = 'active'")
        employees = cur.fetchall()
        
        # Initialize leave balance for each employee
        leave_type_id = cur.lastrowid
        for emp in employees:
            cur.execute("""
                INSERT INTO leave_balance (emp_id, leave_type_id, remaining_days) 
                VALUES (%s, %s, %s)
            """, (emp['emp_id'], leave_type_id, max_days))

        mysql.connection.commit()
        flash('Leave type added successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error adding leave type: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_leave_types'))

@app.route('/admin/leave_type/edit/<int:leave_type_id>', methods=['POST'])
def edit_leave_type(leave_type_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    leave_name = request.form['leave_name']
    description = request.form['description']
    new_max_days = int(request.form['max_days'])
    half_day_allowed = 1 if request.form.get('half_day_allowed') else 0
    
    cur = mysql.connection.cursor()
    try:
        # Get current max days
        cur.execute("SELECT max_days FROM leave_type WHERE leave_type_id = %s", (leave_type_id,))
        current_max_days = cur.fetchone()['max_days']
        
        # Update leave type
        cur.execute("""
            UPDATE leave_type 
            SET leave_name = %s, description = %s, max_days = %s ,half_day_allowed = %s
            WHERE leave_type_id = %s
        """, (leave_name, description, new_max_days,half_day_allowed, leave_type_id))
        
        # If max days increased, add the difference to all employees' balances
        if new_max_days > current_max_days:
            difference = new_max_days - current_max_days
            cur.execute("""
                UPDATE leave_balance 
                SET remaining_days = remaining_days + %s 
                WHERE leave_type_id = %s
            """, (difference, leave_type_id))

        mysql.connection.commit()
        flash('Leave type updated successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating leave type: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_leave_types'))

@app.route('/admin/leave_type/delete/<int:leave_type_id>', methods=['POST'])
def delete_leave_type(leave_type_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    try:
        # Check if leave type is used in applications
        cur.execute("SELECT COUNT(*) as app_count FROM leave_application WHERE leave_type_id = %s", (leave_type_id,))
        result = cur.fetchone()
        
        if result['app_count'] > 0:
            flash('Cannot delete leave type with existing applications', 'danger')
            return redirect(url_for('manage_leave_types'))
        
        # Delete from leave_balance first
        cur.execute("DELETE FROM leave_balance WHERE leave_type_id = %s", (leave_type_id,))
        
        # Then delete from leave_type
        cur.execute("DELETE FROM leave_type WHERE leave_type_id = %s", (leave_type_id,))
        mysql.connection.commit()
        flash('Leave type deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting leave type: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_leave_types'))

# Leave Management
@app.route('/admin/leaves')
def manage_leaves():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    status = request.args.get('status', 'pending')
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT la.*, e.first_name, e.last_name, lt.leave_name 
        FROM leave_application la 
        JOIN employee e ON la.emp_id = e.emp_id 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE la.status = %s 
        ORDER BY la.applied_on DESC
    """, (status,))
    leaves = cur.fetchall()
    cur.close()
    
    return render_template('manage_leaves.html', leaves=leaves, status=status)

@app.route('/admin/leave/action/<int:leave_id>', methods=['POST'])
def leave_action(leave_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    action = request.form['action']
    comments = request.form.get('comments', '')
    admin_id = session['admin_id']
    
    cur = mysql.connection.cursor()
    try:
        # Get leave details
        cur.execute("""
            SELECT emp_id, leave_type_id, start_date, end_date, leave_duration
            FROM leave_application 
            WHERE leave_id = %s
        """, (leave_id,))
        leave = cur.fetchone()
        
        if not leave:
            flash('Leave application not found', 'danger')
            return redirect(url_for('manage_leaves'))
        
        # Calculate days based on duration
        start_date = leave['start_date']
        end_date = leave['end_date']
        days = calculate_leave_days(start_date, end_date, leave['leave_duration'])
        
        # Update leave application
        cur.execute("""
            UPDATE leave_application 
            SET status = %s, processed_by = %s, processed_on = NOW(), comments = %s 
            WHERE leave_id = %s
        """, (action, admin_id, comments, leave_id))
        
        # If approved, update leave balance
        if action == 'approved':
            cur.execute("""
                UPDATE leave_balance 
                SET remaining_days = remaining_days - %s 
                WHERE emp_id = %s AND leave_type_id = %s
            """, (days, leave['emp_id'], leave['leave_type_id']))
        
        mysql.connection.commit()
        flash(f'Leave application {action} successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error processing leave application: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_leaves'))

# Attendance Management
@app.route('/admin/attendance')
def manage_attendance():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    date_filter = request.args.get('date', date.today().strftime('%Y-%m-%d'))
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT a.*, e.first_name, e.last_name, e.employee_id 
        FROM attendance a 
        JOIN employee e ON a.emp_id = e.emp_id 
        WHERE DATE(a.check_in) = %s 
        ORDER BY a.check_in
    """, (date_filter,))
    attendance = cur.fetchall()
    
    cur.execute("""
        SELECT e.emp_id, e.first_name, e.last_name, e.employee_id 
        FROM employee e 
        WHERE e.status = 'active' AND e.emp_id NOT IN (
            SELECT emp_id FROM attendance WHERE DATE(check_in) = %s
        )
    """, (date_filter,))
    absent_employees = cur.fetchall()
    
    cur.close()
    
    return render_template('manage_attendance.html', 
                         attendance=attendance,
                         absent_employees=absent_employees,
                         date_filter=date_filter)

@app.route('/admin/attendance/manual_entry', methods=['POST'])
def manual_attendance_entry():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    emp_id = request.form['emp_id']
    date_str = request.form['date']
    check_in = request.form['check_in']
    check_out = request.form.get('check_out', None)
    
    check_in_datetime = f"{date_str} {check_in}"
    check_out_datetime = f"{date_str} {check_out}" if check_out else None
    
    total_hours = calculate_work_hours(check_in_datetime, check_out_datetime) if check_out else None
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO attendance (emp_id, check_in, check_out, total_hours, status) 
            VALUES (%s, %s, %s, %s, 'present')
        """, (emp_id, check_in_datetime, check_out_datetime, total_hours))
        mysql.connection.commit()
        flash('Attendance recorded successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error recording attendance: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('manage_attendance', date=date_str))

@app.route('/admin/attendance/update/<int:att_id>', methods=['POST'])
def update_attendance(att_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    check_in = request.form['check_in']
    check_out = request.form.get('check_out', None)
    
    total_hours = calculate_work_hours(check_in, check_out) if check_out else None
    
    cur = mysql.connection.cursor()
    try:
        if check_out:
            cur.execute("""
                UPDATE attendance 
                SET check_in = %s, check_out = %s, total_hours = %s 
                WHERE att_id = %s
            """, (check_in, check_out, total_hours, att_id))
        else:
            cur.execute("""
                UPDATE attendance 
                SET check_in = %s, check_out = NULL, total_hours = NULL 
                WHERE att_id = %s
            """, (check_in, att_id))
        
        mysql.connection.commit()
        flash('Attendance updated successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating attendance: {str(e)}', 'danger')
    finally:
        cur.close()
    
    date_str = check_in.split()[0]
    return redirect(url_for('manage_attendance', date=date_str))

@app.route('/admin/attendance/delete/<int:att_id>', methods=['POST'])
def delete_attendance(att_id):
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    try:
        # Get date before deleting for redirect
        cur.execute("SELECT DATE(check_in) as date FROM attendance WHERE att_id = %s", (att_id,))
        date_str = cur.fetchone()['date']
        
        cur.execute("DELETE FROM attendance WHERE att_id = %s", (att_id,))
        mysql.connection.commit()
        flash('Attendance record deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting attendance record: {str(e)}', 'danger')
        return redirect(url_for('manage_attendance'))
    finally:
        cur.close()
    
    return redirect(url_for('manage_attendance', date=date_str))

# Reports
@app.route('/admin/reports/attendance')
def attendance_report():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    emp_id = request.args.get('emp_id', None)
    
    cur = mysql.connection.cursor()
    
    # Get all active employees for filter dropdown
    cur.execute("SELECT emp_id, first_name, last_name, employee_id FROM employee WHERE status = 'active'")
    employees = cur.fetchall()
    
    # Build query based on filters
    query = """
        SELECT a.*, e.first_name, e.last_name, e.employee_id 
        FROM attendance a 
        JOIN employee e ON a.emp_id = e.emp_id 
        WHERE 1=1
    """
    params = []

    # Add date filters if provided
    if start_date:
        query += " AND DATE(a.check_in) >= %s"
        params.append(start_date)
    if end_date:
        query += " AND DATE(a.check_in) <= %s"
        params.append(end_date)
    
    if emp_id:
        query += " AND a.emp_id = %s"
        params.append(emp_id)
    
    query += " ORDER BY a.check_in"
    
    cur.execute(query, tuple(params))
    attendance = cur.fetchall()
    
    cur.close()
    
    return render_template('attendance_report.html', 
                         attendance=attendance,
                         employees=employees,
                         start_date=start_date,
                         end_date=end_date,
                         selected_emp_id=int(emp_id) if emp_id else None)

@app.route('/admin/reports/export_leave')
def export_leave():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    # Get filter parameters
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    emp_id = request.args.get('emp_id', None)
    
    cur = mysql.connection.cursor()
    
    # Build query based on filters (same as leave_report)
    query = """
        SELECT e.employee_id, e.first_name, e.last_name, 
               lt.leave_name, la.start_date, la.end_date, 
               DATEDIFF(la.end_date, la.start_date) + 1 as days,
               la.reason, la.status, la.applied_on,
               la.processed_on, la.comments
        FROM leave_application la 
        JOIN employee e ON la.emp_id = e.emp_id 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE 1=1
    """
    params = []
    
    if start_date:
        query += " AND la.start_date >= %s"
        params.append(start_date)
    if end_date:
        query += " AND la.end_date <= %s"
        params.append(end_date)
    
    if emp_id:
        query += " AND la.emp_id = %s"
        params.append(emp_id)
    
    query += " ORDER BY la.start_date DESC"
    
    cur.execute(query, tuple(params))
    leaves = cur.fetchall()
    cur.close()
    
    # Create CSV content
    csv_data = []
    # Add header
    csv_data.append("Employee ID,First Name,Last Name,Leave Type,Start Date,End Date,Days,Reason,Status,Applied On,Processed On,Comments\n")
    
    # Add rows
    for leave in leaves:
        row = [
            str(leave['employee_id']),
            str(leave['first_name']),
            str(leave['last_name']),
            str(leave['leave_name']),
            leave['start_date'].strftime('%Y-%m-%d') if leave['start_date'] else '',
            leave['end_date'].strftime('%Y-%m-%d') if leave['end_date'] else '',
            str(leave['days']),
            f'"{str(leave["reason"])}"',  # Wrap in quotes to handle commas
            str(leave['status']),
            leave['applied_on'].strftime('%Y-%m-%d %H:%M:%S') if leave['applied_on'] else '',
            leave['processed_on'].strftime('%Y-%m-%d %H:%M:%S') if leave['processed_on'] else '',
            f'"{str(leave["comments"])}"' if leave['comments'] else ''
        ]
        csv_data.append(','.join(row) + '\n')
    
    # Convert to bytes
    output = BytesIO()
    output.write(''.join(csv_data).encode('utf-8'))
    output.seek(0)
    
    # Generate filename
    filename = f"leave_report_{start_date}_to_{end_date}.csv" if start_date and end_date else "leave_report_all.csv"
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )



@app.route('/admin/reports/leave')
def leave_report():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    emp_id = request.args.get('emp_id', None)
    
    cur = mysql.connection.cursor()
    
    # Get all active employees for filter dropdown
    cur.execute("SELECT emp_id, first_name, last_name, employee_id FROM employee WHERE status = 'active'")
    employees = cur.fetchall()
    
    # Build query based on filters
    query = """
        SELECT la.*, e.first_name, e.last_name, e.employee_id, lt.leave_name 
        FROM leave_application la 
        JOIN employee e ON la.emp_id = e.emp_id 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE 1=1
    """
    params = []
    
    # Add date filters if provided
    if start_date:
        query += " AND la.start_date >= %s"
        params.append(start_date)
    if end_date:
        query += " AND la.end_date <= %s"
        params.append(end_date)
    
    if emp_id:
        query += " AND la.emp_id = %s"
        params.append(emp_id)
    
    query += " ORDER BY la.start_date DESC"
    
    cur.execute(query, tuple(params))
    leaves = cur.fetchall()
    
    cur.close()
    
    return render_template('leave_report.html', 
                         leaves=leaves,
                         employees=employees,
                         start_date=start_date,
                         end_date=end_date,
                         selected_emp_id=int(emp_id) if emp_id else None)

@app.route('/admin/reports/export_attendance')
def export_attendance():
    if not is_admin_logged_in():
        return redirect(url_for('login'))
    
 # Get filter parameters with proper defaults
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    emp_id = request.args.get('emp_id', None)
    
    cur = mysql.connection.cursor()
    
    # Build query based on filters
    query = """
        SELECT e.employee_id, e.first_name, e.last_name, 
               a.check_in, 
               a.check_out,
               a.total_hours,
               DATE(a.check_in) as date 
        FROM attendance a 
        JOIN employee e ON a.emp_id = e.emp_id 
        WHERE 1=1    
   """
    params = []
    
    # Add date filters if provided
    if start_date:
        query += " AND DATE(a.check_in) >= %s"
        params.append(start_date)
    if end_date:
        query += " AND DATE(a.check_in) <= %s"
        params.append(end_date)

    # Add employee filter if provided
    if emp_id:
        query += " AND a.emp_id = %s"
        params.append(emp_id)
    
    query += " ORDER BY e.employee_id, a.check_in"
    
    cur.execute(query, tuple(params))
    attendance = cur.fetchall()
    cur.close()
    
    # Create CSV content as string first
    csv_data = []
    # Add header
    csv_data.append("Employee ID,First Name,Last Name,Date,Check In,Check Out,Total Hours\n")
    
   # Add rows

    for record in attendance:

        date_str = record['check_in'].strftime('%Y-%m-%d') if record['check_in'] else ''

        check_in_time = record['check_in'].strftime('%H:%M:%S') if record['check_in'] else ''

        check_out_time = record['check_out'].strftime('%H:%M:%S') if record['check_out'] else ''

        row = [

            str(record['employee_id']),

            str(record['first_name']),

            str(record['last_name']),

            date_str,

            check_in_time,

            check_out_time,

            str(record['total_hours'] or '')

        ]

        csv_data.append(','.join(row) + '\n')

    # Convert to bytes

    output = BytesIO()

    output.write(''.join(csv_data).encode('utf-8'))

    output.seek(0)

    # Generate filename

    filename = f"attendance_report_{start_date}_to_{end_date}.csv" if start_date and end_date else "attendance_report.csv"

    return send_file(

        output,

        mimetype='text/csv',

        as_attachment=True,

        download_name=filename

    )
 

# Employee Dashboard
@app.route('/employee/dashboard')
def employee_dashboard():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    employee = get_employee_details(emp_id)
    
    cur = mysql.connection.cursor()
    
    # Get today's attendance
    today = date.today().strftime('%Y-%m-%d')
    cur.execute("""
        SELECT * FROM attendance 
        WHERE emp_id = %s AND DATE(check_in) = %s
    """, (emp_id, today))
    today_attendance = cur.fetchone()

    # Check if previous day wasn't checked out
    yesterday = (date.today() - timedelta(days=1)).strftime('%Y-%m-%d')
    cur.execute("""
        SELECT * FROM attendance 
        WHERE emp_id = %s AND DATE(check_in) = %s AND check_out IS NULL
    """, (emp_id, yesterday))
    has_pending_checkout = cur.fetchone() is not None
    
    # Get leave balance
    cur.execute("""
        SELECT lt.leave_name, lb.remaining_days, lt.max_days 
        FROM leave_balance lb 
        JOIN leave_type lt ON lb.leave_type_id = lt.leave_type_id 
        WHERE lb.emp_id = %s
    """, (emp_id,))
    leave_balance = cur.fetchall()
    
    # Get recent attendance (last 5 days)
    cur.execute("""
        SELECT DATE(check_in) as date, 
               TIME(check_in) as check_in_time, 
               TIME(check_out) as check_out_time, 
               total_hours 
        FROM attendance 
        WHERE emp_id = %s 
        ORDER BY date DESC 
        LIMIT 5
    """, (emp_id,))
    recent_attendance = cur.fetchall()
    
    # Get pending leave applications
    cur.execute("""
        SELECT la.*, lt.leave_name 
        FROM leave_application la 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE la.emp_id = %s AND la.status = 'pending' 
        ORDER BY la.applied_on DESC
    """, (emp_id,))
    pending_leaves = cur.fetchall()
    
    cur.close()
    
    return render_template('employee_dashboard.html', 
                         employee=employee,
                         today_attendance=today_attendance,
                         has_pending_checkout=has_pending_checkout,
                         leave_balance=leave_balance,
                         recent_attendance=recent_attendance,
                         pending_leaves=pending_leaves)

# Employee Attendance
@app.route('/employee/attendance')
def employee_attendance():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    month = request.args.get('month', date.today().strftime('%Y-%m'))
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT DATE(check_in) as date, 
               TIME(check_in) as check_in, 
               TIME(check_out) as check_out, 
               total_hours 
        FROM attendance 
        WHERE emp_id = %s AND DATE_FORMAT(check_in, '%%Y-%%m') = %s 
        ORDER BY date
    """, (emp_id, month))
    attendance = cur.fetchall()
    
    # Calculate summary
    total_days = len(attendance)
    total_hours = sum(record['total_hours'] or 0 for record in attendance)
    avg_hours = total_hours / total_days if total_days > 0 else 0
    
    cur.close()
    
    return render_template('employee_attendance.html', 
                         attendance=attendance,
                         month=month,
                         total_days=total_days,
                         total_hours=round(total_hours, 2),
                         avg_hours=round(avg_hours, 2))

@app.route('/employee/check_in', methods=['POST'])
def employee_check_in():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    emp_id = session['emp_id']
    current_time = get_current_datetime()
    cur = mysql.connection.cursor()
    try:
        # Check if already checked in today
        today = date.today().strftime('%Y-%m-%d')
        cur.execute("""
            SELECT * FROM attendance 
            WHERE emp_id = %s AND DATE(check_in) = %s AND check_out IS NULL
        """, (emp_id, today))
        existing = cur.fetchone()
        if existing:
            flash('You have already checked in today and not checked out yet', 'warning')
            return redirect(url_for('employee_dashboard'))
        # Check if previous day wasn't checked out
        yesterday = (date.today() - timedelta(days=1)).strftime('%Y-%m-%d')
        cur.execute("""
            SELECT * FROM attendance 
            WHERE emp_id = %s AND DATE(check_in) = %s AND check_out IS NULL
        """, (emp_id, yesterday))
        previous_day = cur.fetchone()
        if previous_day:
            flash('You cannot check in today because you were not checked out yesterday. Please contact admin.', 'danger')
            return redirect(url_for('employee_dashboard'))
        # Record check-in with status
        cur.execute("""
            INSERT INTO attendance (emp_id, check_in, status) 
            VALUES (%s, %s, 'present')
        """, (emp_id, current_time))
        mysql.connection.commit()
        flash('Check-in recorded successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error recording check-in: {str(e)}', 'danger')
    finally:
        cur.close()
    return redirect(url_for('employee_dashboard'))


@app.route('/employee/check_out', methods=['POST'])
def employee_check_out():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    current_time = get_current_datetime()
    
    cur = mysql.connection.cursor()
    try:
        # Get today's check-in
        today = date.today().strftime('%Y-%m-%d')
        cur.execute("""
            SELECT * FROM attendance 
            WHERE emp_id = %s AND DATE(check_in) = %s AND check_out IS NULL
        """, (emp_id, today))
        attendance = cur.fetchone()
        
        if not attendance:
            flash('You need to check in first', 'warning')
            return redirect(url_for('employee_dashboard'))
        
        # Calculate work hours
        check_in = attendance['check_in'].strftime('%Y-%m-%d %H:%M:%S')
        total_hours = calculate_work_hours(check_in, current_time)
        
        # Record check-out
        cur.execute("""
            UPDATE attendance 
            SET check_out = %s, total_hours = %s 
            WHERE att_id = %s
        """, (current_time, total_hours, attendance['att_id']))
        mysql.connection.commit()
        flash('Check-out recorded successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error recording check-out: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('employee_dashboard'))

# Employee Leave Management
@app.route('/employee/leaves')
def employee_leaves():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    status = request.args.get('status', 'all')
    
    cur = mysql.connection.cursor()
    
    # Get leave balance
    cur.execute("""
        SELECT lt.leave_name, lb.remaining_days, lt.max_days 
        FROM leave_balance lb 
        JOIN leave_type lt ON lb.leave_type_id = lt.leave_type_id 
        WHERE lb.emp_id = %s
    """, (emp_id,))
    leave_balance = cur.fetchall()
    
    # Get leave applications
    query = """
        SELECT la.*, lt.leave_name 
        FROM leave_application la 
        JOIN leave_type lt ON la.leave_type_id = lt.leave_type_id 
        WHERE la.emp_id = %s
    """
    params = [emp_id]
    
    if status != 'all':
        query += " AND la.status = %s"
        params.append(status)
    
    query += " ORDER BY la.applied_on DESC"
    
    cur.execute(query, tuple(params))
    leaves = cur.fetchall()
    
    # Get leave types for new application form
    cur.execute("SELECT * FROM leave_type")
    leave_types = cur.fetchall()
    
    cur.close()
    
    return render_template('employee_leaves.html', 
                         leave_balance=leave_balance,
                         leaves=leaves,
                         leave_types=leave_types,
                         status=status)

@app.route('/employee/leave/apply', methods=['POST'])
def apply_leave():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    leave_type_id = request.form['leave_type_id']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    leave_duration = request.form['leave_duration']  # 'full_day', 'first_half', 'second_half'
    reason = request.form['reason']
    
    # Convert to date objects
    start_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_dt = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Validate dates based on leave duration
    if not validate_leave_dates(start_dt, end_dt, leave_duration):
        if leave_duration == 'full_day':
            flash('End date must be after or same as start date for full day leave', 'danger')
        else:
            flash('Start and end date must be same for half-day leave', 'danger')
        return redirect(url_for('employee_leaves'))
    
    # Calculate days
    days = calculate_leave_days(start_dt, end_dt, leave_duration)
    
    cur = mysql.connection.cursor()
    try:
        # Check leave balance and if half-day is allowed
        cur.execute("""
            SELECT lt.max_days, lt.half_day_allowed, lb.remaining_days 
            FROM leave_balance lb 
            JOIN leave_type lt ON lb.leave_type_id = lt.leave_type_id 
            WHERE lb.emp_id = %s AND lb.leave_type_id = %s
        """, (emp_id, leave_type_id))
        result = cur.fetchone()
        
        if not result:
            flash('Leave type not found', 'danger')
            return redirect(url_for('employee_leaves'))
            
        if leave_duration != 'full_day' and not result['half_day_allowed']:
            flash('Half-day leave is not allowed for this leave type', 'danger')
            return redirect(url_for('employee_leaves'))
            
        if result['remaining_days'] < days:
            flash(f'Not enough leave balance. You have {result["remaining_days"]} days remaining but requested {days} days.', 'danger')
            return redirect(url_for('employee_leaves'))
        
        # Check for overlapping leave applications - simplified query
        cur.execute("""
            SELECT COUNT(*) as overlap_count 
            FROM leave_application 
            WHERE emp_id = %s 
            AND status = 'approved'
            AND (
                (%s BETWEEN start_date AND end_date)
                OR (%s BETWEEN start_date AND end_date)
                OR (start_date BETWEEN %s AND %s)
                OR (end_date BETWEEN %s AND %s)
            )
        """, (
            emp_id,
            start_date, end_date,
            start_date, end_date,
            start_date, end_date
        ))
        overlap = cur.fetchone()['overlap_count'] > 0
        
        if overlap:
            flash('You already have an approved leave during this period', 'danger')
            return redirect(url_for('employee_leaves'))
 
        # Apply leave
        cur.execute("""
            INSERT INTO leave_application 
            (emp_id, leave_type_id, start_date, end_date, leave_duration, reason) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (emp_id, leave_type_id, start_date, end_date, leave_duration, reason))
        
        mysql.connection.commit()
        flash('Leave application submitted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error applying for leave: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('employee_leaves'))

@app.route('/employee/leave/cancel/<int:leave_id>', methods=['POST'])
def cancel_leave(leave_id):
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    
    cur = mysql.connection.cursor()
    try:
        # Check if leave can be cancelled (status is pending)
        cur.execute("""
            SELECT status FROM leave_application 
            WHERE leave_id = %s AND emp_id = %s
        """, (leave_id, emp_id))
        leave = cur.fetchone()
        
        if not leave:
            flash('Leave application not found', 'danger')
            return redirect(url_for('employee_leaves'))
        
        if leave['status'] != 'pending':
            flash('Only pending leaves can be cancelled', 'danger')
            return redirect(url_for('employee_leaves'))
        
        # Delete leave application
        cur.execute("""
            DELETE FROM leave_application 
            WHERE leave_id = %s
        """, (leave_id,))
        mysql.connection.commit()
        flash('Leave application cancelled successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error cancelling leave: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('employee_leaves'))

# Employee Profile
@app.route('/employee/profile')
def employee_profile():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    employee = get_employee_details(emp_id)
    
    return render_template('employee_profile.html', employee=employee)

@app.route('/employee/change_password', methods=['POST'])
def change_employee_password():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    current_password = request.form['current_password'].encode('utf-8')
    new_password = request.form['new_password']
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long', 'danger')
        return redirect(url_for('employee_profile'))
    
    cur = mysql.connection.cursor()
    try:
        # Verify current password
        cur.execute("SELECT password_hash FROM employee WHERE emp_id = %s", (emp_id,))
        employee = cur.fetchone()
        
        if not employee or not bcrypt.checkpw(current_password, employee['password_hash'].encode('utf-8')):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('employee_profile'))
        
        # Update password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("""
            UPDATE employee 
            SET password_hash = %s 
            WHERE emp_id = %s
        """, (hashed_password, emp_id))
        mysql.connection.commit()
        flash('Password changed successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error changing password: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('employee_profile'))

@app.route('/employee/update_profile_pic', methods=['POST'])
def update_employee_profile_pic():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    
    if 'profile_pic' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('employee_profile'))
    
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('employee_profile'))
    
    if file and allowed_file(file.filename):
        # Get employee details to use the employee_id in filename
        cur = mysql.connection.cursor()
        cur.execute("SELECT employee_id FROM employee WHERE emp_id = %s", (emp_id,))
        employee = cur.fetchone()
        cur.close()
        
        if not employee:
            flash('Employee not found', 'danger')
            return redirect(url_for('employee_profile'))
        
        filename = secure_filename(f"{employee['employee_id']}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Delete old profile pic if exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT profile_pic FROM employee WHERE emp_id = %s", (emp_id,))
        old_pic = cur.fetchone()['profile_pic']
        
        if old_pic and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], old_pic)):
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_pic))
            except:
                pass
        
        # Save new file
        file.save(filepath)
        
        # Update database
        try:
            cur.execute("""
                UPDATE employee 
                SET profile_pic = %s 
                WHERE emp_id = %s
            """, (filename, emp_id))
            mysql.connection.commit()
            flash('Profile picture updated successfully!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating profile picture: {str(e)}', 'danger')
        finally:
            cur.close()
    else:
        flash('Allowed file types are: png, jpg, jpeg, gif', 'danger')
    
    return redirect(url_for('employee_profile'))


# Calendar View
@app.route('/employee/calendar')
def employee_calendar():
    if not is_employee_logged_in():
        return redirect(url_for('login'))
    
    emp_id = session['emp_id']
    year = request.args.get('year', date.today().year)
    month = request.args.get('month', date.today().month)
    
    cur = mysql.connection.cursor()
    
    # Get attendance for the month
    cur.execute("""
        SELECT DATE(check_in) as date, 
               TIME(check_in) as check_in, 
               TIME(check_out) as check_out, 
               total_hours 
        FROM attendance 
        WHERE emp_id = %s AND YEAR(check_in) = %s AND MONTH(check_in) = %s 
        ORDER BY date
    """, (emp_id, year, month))
    attendance = cur.fetchall()
    
    # Get leaves for the month
    cur.execute("""
        SELECT start_date, end_date, status 
        FROM leave_application 
        WHERE emp_id = %s AND (
            (YEAR(start_date) = %s AND MONTH(start_date) = %s) OR
            (YEAR(end_date) = %s AND MONTH(end_date) = %s)
        )
    """, (emp_id, year, month, year, month))
    leaves = cur.fetchall()
    
    cur.close()
    
    # Create calendar data structure
    calendar_data = []
    
    # Get first and last day of month
    first_day = date(int(year), int(month), 1)
    last_day = date(int(year), int(month) + 1, 1) - timedelta(days=1) if int(month) < 12 else date(int(year) + 1, 1, 1) - timedelta(days=1)
    
    # Get days from previous month to show
    prev_month_days = (first_day.weekday() + 1) % 7  # +1 for Monday as first day
    
    # Add days from previous month
    prev_month_last_day = first_day - timedelta(days=1)
    for day in range(prev_month_last_day.day - prev_month_days + 1, prev_month_last_day.day + 1):
        calendar_data.append({
            'day': day,
            'month': 'prev',
            'attendance': None,
            'leave': None
        })
    
    # Add days from current month
    for day in range(1, last_day.day + 1):
        current_date = date(int(year), int(month), day)
        date_str = current_date.strftime('%Y-%m-%d')
        
        # Find attendance for this day
        day_attendance = next((a for a in attendance if a['date'] == current_date), None)
        
        # Find leave for this day
        day_leave = None
        for leave in leaves:
            if leave['start_date'] <= current_date <= leave['end_date']:
                day_leave = leave
                break
        
        calendar_data.append({
            'day': day,
            'month': 'current',
            'attendance': day_attendance,
            'leave': day_leave
        })
    
    # Add days from next month to complete the grid
    next_month_days = (6 - last_day.weekday()) % 7  # 6 for Sunday as last day
    for day in range(1, next_month_days + 1):
        calendar_data.append({
            'day': day,
            'month': 'next',
            'attendance': None,
            'leave': None
        })
    
    # Split into weeks (7 days each)
    weeks = [calendar_data[i:i + 7] for i in range(0, len(calendar_data), 7)]
    
    return render_template('employee_calendar.html', 
                         weeks=weeks,
                         year=year,
                         month=month,
                         month_name=first_day.strftime('%B'))

if __name__ == '__main__':
    app.run(debug=True)
