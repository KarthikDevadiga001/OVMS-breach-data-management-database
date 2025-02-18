from flask import Flask, request, jsonify, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Database configuration
class Config:
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:03040506@localhost:5432/OVMS'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class StandardBreachName(db.Model):
    __tablename__ = 'standard_breach_names'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    breaches = db.relationship('Breach', backref='standard_breach', lazy=True)

class Department(db.Model):
    __tablename__ = 'department'
    dept_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    systems = db.relationship('System', backref='department', lazy=True)
    locations = db.relationship('Location', backref='department', lazy=True)

class Location(db.Model):
    __tablename__ = 'location'
    location_id = db.Column(db.Integer, primary_key=True)
    place_name = db.Column(db.String(100), nullable=False)
    floor = db.Column(db.String(50), nullable=False)
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id', ondelete='CASCADE'), nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'cyber_professional'
    id = db.Column('prof_id', db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    systems = db.relationship('System', backref='professional', lazy=True)
    breaches = db.relationship('Breach', backref='professional', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class System(db.Model):
    __tablename__ = 'system'
    system_id = db.Column(db.Integer, primary_key=True, autoincrement=False)
    name = db.Column(db.String(100), nullable=False)
    processor = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    d_id = db.Column(db.Integer, db.ForeignKey('department.dept_id', ondelete='CASCADE'), nullable=False)
    p_id = db.Column(db.Integer, db.ForeignKey('cyber_professional.prof_id', ondelete='CASCADE'), nullable=False)
    breaches = db.relationship('Breach', secondary='encounters', backref=db.backref('systems', lazy=True))

class Breach(db.Model):
    __tablename__ = 'breach'
    breach_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    standard_breach_id = db.Column(db.Integer, db.ForeignKey('standard_breach_names.id'), nullable=True)
    status = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    p_id = db.Column(db.Integer, db.ForeignKey('cyber_professional.prof_id', ondelete='CASCADE'), nullable=False)
    compliances = db.relationship('Compliance', secondary='belongs', backref=db.backref('breaches', lazy=True))

class Compliance(db.Model):
    __tablename__ = 'compliance'
    policy_id = db.Column(db.Integer, primary_key=True)
    policy_name = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)

# M:N relationship tables
class Encounters(db.Model):
    __tablename__ = 'encounters'
    sys_id = db.Column(db.Integer, db.ForeignKey('system.system_id', ondelete='CASCADE'), primary_key=True)
    br_id = db.Column(db.Integer, db.ForeignKey('breach.breach_id', ondelete='CASCADE'), primary_key=True)
    __table_args__ = (
        db.PrimaryKeyConstraint('sys_id', 'br_id'),
    )

class Belongs(db.Model):
    __tablename__ = 'belongs'
    b_id = db.Column(db.Integer, db.ForeignKey('breach.breach_id', ondelete='CASCADE'), primary_key=True)
    comp_id = db.Column(db.Integer, db.ForeignKey('compliance.policy_id', ondelete='CASCADE'), primary_key=True)
    __table_args__ = (
        db.PrimaryKeyConstraint('b_id', 'comp_id'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    with app.app_context():
        try:
            # Check if tables exist by querying the User table
            inspector = db.inspect(db.engine)
            tables_exist = inspector.get_table_names()
            
            if not tables_exist:
                # Create all tables if they don't exist
                db.create_all()
                
                # Create initial standard breach names
                standard_breaches = [
                    StandardBreachName(name='SQL Injection', description='Database injection attack through malicious SQL queries'),
                    StandardBreachName(name='Cross-Site Scripting (XSS)', description='Client-side code injection attack'),
                    StandardBreachName(name='Buffer Overflow', description='Memory boundary violation attack'),
                    StandardBreachName(name='DDoS Attack', description='Distributed Denial of Service attack'),
                    StandardBreachName(name='Man-in-the-Middle', description='Network traffic interception attack'),
                    StandardBreachName(name='Phishing Attack', description='Social engineering attack to steal credentials'),
                    StandardBreachName(name='Ransomware', description='Malware that encrypts data for ransom'),
                    StandardBreachName(name='Zero-Day Exploit', description='Attack using previously unknown vulnerability'),
                    StandardBreachName(name='Password Attack', description='Attempt to crack or steal passwords'),
                    StandardBreachName(name='Malware Infection', description='System infection with malicious software')
                ]
                for breach in standard_breaches:
                    db.session.add(breach)
                
                # Create initial departments
                departments = [
                    Department(name='Cybersecurity'),
                    Department(name='Software Development'),
                    Department(name='Research and Development'),
                    Department(name='Human Resources'),
                    Department(name='Quality Assurance')
                ]
                for dept in departments:
                    db.session.add(dept)
                db.session.flush()  # This will assign department IDs
                
                # Create multiple locations for each department
                locations = [
                    # Cybersecurity department locations
                    Location(place_name='Tech Park', floor='3rd Floor', dept_id=departments[0].dept_id),
                    Location(place_name='Security Operations Center', floor='2nd Floor', dept_id=departments[0].dept_id),
                    # Software Development department locations
                    Location(place_name='Innovation Center', floor='2nd Floor', dept_id=departments[1].dept_id),
                    Location(place_name='Development Hub', floor='4th Floor', dept_id=departments[1].dept_id),
                    # R&D department locations
                    Location(place_name='R&D Hub', floor='1st Floor', dept_id=departments[2].dept_id),
                    Location(place_name='Research Lab', floor='5th Floor', dept_id=departments[2].dept_id),
                    # HR department locations
                    Location(place_name='Main Office', floor='Ground Floor', dept_id=departments[3].dept_id),
                    Location(place_name='Training Center', floor='1st Floor', dept_id=departments[3].dept_id),
                    # QA department locations
                    Location(place_name='Quality Wing', floor='4th Floor', dept_id=departments[4].dept_id),
                    Location(place_name='Testing Lab', floor='3rd Floor', dept_id=departments[4].dept_id)
                ]
                for loc in locations:
                    db.session.add(loc)
                
                # Create admin user
                admin = User(username='admin_ovms', role='admin')
                admin.set_password('Admin@OVMS2024')
                db.session.add(admin)

                # Create professional user
                professional = User(username='cyber_pro', role='professional')
                professional.set_password('CyberPro@2024')
                db.session.add(professional)

                db.session.commit()
                print("Database initialized with default data!")
            else:
                print("Database tables already exist, skipping initialization.")
                
        except Exception as e:
            db.session.rollback()
            print(f"Error checking/initializing database: {str(e)}")
            raise

def init_standard_breaches():
    with app.app_context():
        try:
            # Check if standard breaches already exist
            existing_breaches = StandardBreachName.query.count()
            if existing_breaches == 0:
                # Create initial standard breach names
                standard_breaches = [
                    StandardBreachName(name='SQL Injection', description='Database injection attack through malicious SQL queries'),
                    StandardBreachName(name='Cross-Site Scripting (XSS)', description='Client-side code injection attack'),
                    StandardBreachName(name='Buffer Overflow', description='Memory boundary violation attack'),
                    StandardBreachName(name='DDoS Attack', description='Distributed Denial of Service attack'),
                    StandardBreachName(name='Man-in-the-Middle', description='Network traffic interception attack'),
                    StandardBreachName(name='Phishing Attack', description='Social engineering attack to steal credentials'),
                    StandardBreachName(name='Ransomware', description='Malware that encrypts data for ransom'),
                    StandardBreachName(name='Zero-Day Exploit', description='Attack using previously unknown vulnerability'),
                    StandardBreachName(name='Password Attack', description='Attempt to crack or steal passwords'),
                    StandardBreachName(name='Malware Infection', description='System infection with malicious software')
                ]
                for breach in standard_breaches:
                    db.session.add(breach)
                db.session.commit()
                print("Standard breach names initialized successfully!")
            else:
                print("Standard breach names already exist, skipping initialization.")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing standard breach names: {str(e)}")

# Import routes after app initialization to avoid circular imports
from routes import *

if __name__ == '__main__':
    init_standard_breaches()
    app.run(debug=True)

    