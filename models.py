# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
 
db = SQLAlchemy()
 
class Admin(db.Model):
    __tablename__ = 'admin'
    admin_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
 
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
 
class Department(db.Model):
    __tablename__ = 'department'
    dept_id = db.Column(db.Integer, primary_key=True)
    dept_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
 
class Designation(db.Model):
    __tablename__ = 'designation'
    desig_id = db.Column(db.Integer, primary_key=True)
    desig_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
 
class Employee(db.Model):
    __tablename__ = 'employee'
    emp_id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    work_email = db.Column(db.String(100), unique=True, nullable=False)
    personal_email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    join_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date)
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    desig_id = db.Column(db.Integer, db.ForeignKey('designation.desig_id'))
    password_hash = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(255))
    status = db.Column(db.Enum('active', 'inactive'), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
 
    department = db.relationship('Department', backref='employees')
    designation = db.relationship('Designation', backref='employees')
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
 
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
 
class Attendance(db.Model):
    __tablename__ = 'attendance'
    att_id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.Integer, db.ForeignKey('employee.emp_id'), nullable=False)
    check_in = db.Column(db.DateTime, nullable=False)
    check_out = db.Column(db.DateTime)
    total_hours = db.Column(db.Numeric(5, 2))
    status = db.Column(db.Enum('present', 'absent', 'half-day', 'leave'), default='present')
    notes = db.Column(db.Text)
 
    employee = db.relationship('Employee', backref='attendances')
 
class LeaveType(db.Model):
    __tablename__ = 'leave_type'
    leave_type_id = db.Column(db.Integer, primary_key=True)
    leave_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    max_days = db.Column(db.Integer, nullable=False)
 
class LeaveApplication(db.Model):
    __tablename__ = 'leave_application'
    leave_id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.Integer, db.ForeignKey('employee.emp_id'), nullable=False)
    leave_type_id = db.Column(db.Integer, db.ForeignKey('leave_type.leave_type_id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('pending', 'approved', 'rejected'), default='pending')
    applied_on = db.Column(db.DateTime, default=datetime.utcnow)
    processed_by = db.Column(db.Integer, db.ForeignKey('admin.admin_id'))
    processed_on = db.Column(db.DateTime)
    comments = db.Column(db.Text)
 
    employee = db.relationship('Employee', backref='leave_applications')
    leave_type = db.relationship('LeaveType', backref='leave_applications')
    admin = db.relationship('Admin', backref='processed_leaves')
 
class LeaveBalance(db.Model):
    __tablename__ = 'leave_balance'
    balance_id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.Integer, db.ForeignKey('employee.emp_id'), nullable=False)
    leave_type_id = db.Column(db.Integer, db.ForeignKey('leave_type.leave_type_id'), nullable=False)
    remaining_days = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
 
    employee = db.relationship('Employee', backref='leave_balances')
    leave_type = db.relationship('LeaveType', backref='leave_balances')
 
    __table_args__ = (
        db.UniqueConstraint('emp_id', 'leave_type_id', name='unique_employee_leave_type'),
    )