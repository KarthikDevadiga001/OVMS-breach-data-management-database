from app import db

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
    dept_location = db.Column(db.String(100))
    systems = db.relationship('System', backref='department')
    professionals = db.relationship('CyberProfessional', backref='department')

class System(db.Model):
    __tablename__ = 'system'
    system_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    processor = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(15))
    d_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    p_id = db.Column(db.Integer, db.ForeignKey('cyber_professional.prof_id'))

class CyberProfessional(db.Model):
    __tablename__ = 'cyber_professional'
    prof_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    d_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    breaches = db.relationship('Breach', backref='professional')

class Breach(db.Model):
    __tablename__ = 'breach'
    breach_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    standard_breach_id = db.Column(db.Integer, db.ForeignKey('standard_breach_names.id'), nullable=True)
    status = db.Column(db.String(50))
    date = db.Column(db.DateTime, nullable=False)
    cvss_score = db.Column(db.Float)
    p_id = db.Column(db.Integer, db.ForeignKey('cyber_professional.prof_id'))
    reports = db.relationship('Report', backref='breach')
    systems = db.relationship('System', secondary='encounters', backref='breaches')
    compliance_policies = db.relationship('Compliance', secondary='belongs', backref='breaches')

class Compliance(db.Model):
    __tablename__ = 'compliance'
    policy_id = db.Column(db.Integer, primary_key=True)
    policy_name = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer)

class Report(db.Model):
    __tablename__ = 'report'
    report_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date_detected = db.Column(db.DateTime, nullable=False)
    severity = db.Column(db.String(50))
    breach_id = db.Column(db.Integer, db.ForeignKey('breach.breach_id'))

# Association Tables
class Encounters(db.Model):
    __tablename__ = 'encounters'
    sys_id = db.Column(db.Integer, db.ForeignKey('system.system_id'), primary_key=True)
    br_id = db.Column(db.Integer, db.ForeignKey('breach.breach_id'), primary_key=True)

class Belongs(db.Model):
    __tablename__ = 'belongs'
    b_id = db.Column(db.Integer, db.ForeignKey('breach.breach_id'), primary_key=True)
    comp_id = db.Column(db.Integer, db.ForeignKey('compliance.policy_id'), primary_key=True)