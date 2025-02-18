from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, User, Department, System, Breach, Compliance, Encounters, Belongs, StandardBreachName
from datetime import datetime
import re

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('professional_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        selected_role = request.form.get('role')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.role == selected_role:
                login_user(user)
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('professional_dashboard'))
            else:
                flash('Invalid role selected for this user')
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/professional/dashboard')
@login_required
def professional_dashboard():
    if current_user.role != 'professional':
        return redirect(url_for('home'))
    # Get user's recent reports
    recent_breaches = Breach.query.filter_by(p_id=current_user.id).order_by(Breach.date.desc()).limit(5).all()
    return render_template('professional_dashboard.html', breaches=recent_breaches)

@app.route('/professional/report-breach', methods=['GET', 'POST'])
@login_required
def report_breach():
    if current_user.role != 'professional':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Handle breach name (standard or custom)
            breach_name = request.form.get('breach_name')
            standard_breach_id = request.form.get('standard_breach_id')
            
            if standard_breach_id:
                # Using standard breach name
                standard_breach = StandardBreachName.query.get(standard_breach_id)
                if not standard_breach:
                    return jsonify({
                        'success': False,
                        'message': 'Invalid standard breach selected'
                    })
                breach_name = standard_breach.name
            else:
                # New custom breach name, add it to standard breaches
                existing_standard = StandardBreachName.query.filter_by(name=breach_name).first()
                if not existing_standard:
                    new_standard = StandardBreachName(name=breach_name)
                    db.session.add(new_standard)
                    db.session.flush()
                    standard_breach_id = new_standard.id
                else:
                    standard_breach_id = existing_standard.id

            # Process each system first
            systems_data = {}
            for key in request.form:
                if key.startswith('systems['):
                    parts = key.replace(']', '').split('[')
                    index = parts[1]
                    field = parts[2]
                    
                    if index not in systems_data:
                        systems_data[index] = {}
                    systems_data[index][field] = request.form[key]
            
            # Create or update systems first
            system_ids = []
            for system_data in systems_data.values():
                system_id = int(system_data['system_id'])
                
                # Check if system exists
                system = System.query.get(system_id)
                if system:
                    if system.p_id != current_user.id:
                        return jsonify({
                            'success': False,
                            'message': f'System ID {system_id} exists but belongs to another professional'
                        })
                else:
                    system = System(
                        system_id=system_id,
                        name=system_data['system_name'],
                        processor=system_data['processor'],
                        ip_address=system_data['ip_address'],
                        d_id=system_data['department'],
                        p_id=current_user.id
                    )
                    db.session.add(system)
                system_ids.append(system_id)
            
            db.session.flush()
            
            # Create new breach entry
            breach = Breach(
                name=breach_name,
                standard_breach_id=standard_breach_id,
                status=request.form['status'],
                date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
                cvss_score=float(request.form['cvss_score']),
        p_id=current_user.id
    )
            db.session.add(breach)
            db.session.flush()
            
            # Create new compliance entry
            compliance = Compliance(
                policy_name=request.form['policy_name'],
                year=int(request.form['policy_year'])
            )
            db.session.add(compliance)
            db.session.flush()
            
            # Create the belongs relationship
            belongs = Belongs(
                b_id=breach.breach_id,
                comp_id=compliance.policy_id
            )
            db.session.add(belongs)
            
            # Create the encounters relationships
            for system_id in system_ids:
                encounter = Encounters(
                    sys_id=system_id,
                    br_id=breach.breach_id
                )
                db.session.add(encounter)
            
            db.session.commit()
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'message': 'Breach report submitted successfully'})
            else:
                flash('Breach report submitted successfully')
                return redirect(url_for('professional_dashboard'))
                
        except Exception as e:
            db.session.rollback()
            error_message = str(e)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': f'Error submitting report: {error_message}'})
            else:
                flash(f'Error submitting report: {error_message}')
                return redirect(url_for('report_breach'))
    
    # GET request - show the form
    departments = Department.query.all()
    standard_breaches = StandardBreachName.query.order_by(StandardBreachName.name).all()
    return render_template('report_breach.html', departments=departments, standard_breaches=standard_breaches)

def get_severity(cvss_score):
    if cvss_score <= 3.9:
        return 'low'
    elif cvss_score <= 6.9:
        return 'medium'
    elif cvss_score <= 8.9:
        return 'high'
    else:
        return 'critical'

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    # Get statistics
    total_breaches = Breach.query.count()
    active_breaches = Breach.query.filter_by(status='Active').count()
    total_systems = System.query.count()
    
    # Get all breaches with related data
    breaches = Breach.query\
        .join(User, Breach.p_id == User.id)\
        .join(Encounters, Breach.breach_id == Encounters.br_id)\
        .join(System, System.system_id == Encounters.sys_id)\
        .join(Department, System.d_id == Department.dept_id)\
        .order_by(Breach.date.desc()).all()
    
    return render_template('admin_dashboard.html',
                        breaches=breaches,
                        total_breaches=total_breaches,
                        active_breaches=active_breaches,
                        total_systems=total_systems,
                        get_severity=get_severity)

@app.route('/admin/generate-report', methods=['GET', 'POST'])
@login_required
def generate_report():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    # Get filter parameters
    time_period = request.args.get('time_period', 'all')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    breach_type = request.args.get('breach_type')
    
    # Base query with joins
    query = Breach.query\
        .join(User, Breach.p_id == User.id)\
        .join(Encounters, Breach.breach_id == Encounters.br_id)\
        .join(System, System.system_id == Encounters.sys_id)\
        .join(Department, System.d_id == Department.dept_id)\
        .options(db.joinedload(Breach.systems))\
        .options(db.joinedload(Breach.professional))
    
    # Apply breach type filter
    if breach_type:
        query = query.filter(Breach.standard_breach_id == breach_type)
    
    # Apply time filters
    today = datetime.now().date()
    if time_period == 'last_month':
        last_month = today.replace(day=1)
        if last_month.month == 1:
            last_month = last_month.replace(year=last_month.year - 1, month=12)
        else:
            last_month = last_month.replace(month=last_month.month - 1)
        query = query.filter(Breach.date >= last_month)
    elif time_period == 'last_3_months':
        three_months_ago = today.replace(day=1)
        for _ in range(3):
            if three_months_ago.month == 1:
                three_months_ago = three_months_ago.replace(year=three_months_ago.year - 1, month=12)
            else:
                three_months_ago = three_months_ago.replace(month=three_months_ago.month - 1)
        query = query.filter(Breach.date >= three_months_ago)
    elif time_period == 'last_6_months':
        six_months_ago = today.replace(day=1)
        for _ in range(6):
            if six_months_ago.month == 1:
                six_months_ago = six_months_ago.replace(year=six_months_ago.year - 1, month=12)
            else:
                six_months_ago = six_months_ago.replace(month=six_months_ago.month - 1)
        query = query.filter(Breach.date >= six_months_ago)
    elif time_period == 'last_year':
        one_year_ago = today.replace(year=today.year - 1)
        query = query.filter(Breach.date >= one_year_ago)
    elif time_period == 'custom' and start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        query = query.filter(Breach.date.between(start, end))
    
    # Get filtered breaches
    breaches = query.order_by(Breach.date.desc()).all()
    
    # Calculate statistics based on filtered data
    total_breaches = len(breaches)
    status_counts = {
        'Active': sum(1 for b in breaches if b.status == 'Active'),
        'Resolved': sum(1 for b in breaches if b.status == 'Resolved'),
        'Under Investigation': sum(1 for b in breaches if b.status == 'Under Investigation')
    }
    
    avg_cvss = sum(b.cvss_score for b in breaches) / total_breaches if total_breaches > 0 else 0
    
    # Get all standard breach names for the filter
    standard_breaches = StandardBreachName.query.order_by(StandardBreachName.name).all()
    
    return render_template('generate_report.html',
                         breaches=breaches,
                         total_breaches=total_breaches,
                         status_counts=status_counts,
                         avg_cvss=avg_cvss,
                         get_severity=get_severity,
                         time_period=time_period,
                         start_date=start_date,
                         end_date=end_date,
                         standard_breaches=standard_breaches,
                         selected_breach_type=breach_type)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/admin/add-professional', methods=['GET', 'POST'])
@login_required
def add_professional():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if not username or not password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('add_professional'))

        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]{5,20}$', username):
            flash('Username must be 5-20 characters long and can only contain letters, numbers, and underscores', 'error')
            return redirect(url_for('add_professional'))

        # Validate password format
        if not re.match(r'^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$', password):
            flash('Password must meet all requirements: 8+ characters, uppercase, lowercase, number, and special character', 'error')
            return redirect(url_for('add_professional'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('add_professional'))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('add_professional'))

        try:
            # Create new professional user
            new_professional = User(
                username=username,
                role='professional'
            )
            new_professional.set_password(password)
            db.session.add(new_professional)
            db.session.commit()
            flash('Professional added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding professional: {str(e)}', 'error')
            return redirect(url_for('add_professional'))

    return render_template('add_professional.html')

@app.route('/admin/breach-report/<int:breach_id>')
@login_required
def breach_report(breach_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    breach = Breach.query.get_or_404(breach_id)
    system = breach.systems[0]  # Get the first system associated with the breach
    compliance = breach.compliances[0]  # Get the first compliance policy associated with the breach
    
    return render_template('breach_report.html',
                         breach=breach,
                         system=system,
                         compliance=compliance,
                         get_severity=get_severity)

@app.route('/admin/systems')
@login_required
def systems_grid():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    systems = System.query\
        .join(Department)\
        .options(db.joinedload(System.breaches))\
        .options(db.joinedload(System.department))\
        .all()
    
    departments = Department.query.all()
    
    return render_template('systems_grid.html',
                         systems=systems,
                         departments=departments,
                         get_severity=get_severity)

@app.route('/check_username/<username>')
def check_username(username):
    user = User.query.filter_by(username=username).first()
    return jsonify({'available': user is None})

@app.route('/professional/update-breach-status/<int:breach_id>', methods=['POST'])
@login_required
def update_breach_status(breach_id):
    if current_user.role != 'professional':
        return jsonify({'success': False, 'message': 'Unauthorized access'})
    
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'success': False, 'message': 'No status provided'})
        
        breach = Breach.query.get_or_404(breach_id)
        
        # Verify the breach belongs to the current professional
        if breach.p_id != current_user.id:
            return jsonify({'success': False, 'message': 'Unauthorized to modify this breach'})
        
        # Update the status
        breach.status = new_status
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Status updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error updating status: {str(e)}'
        })

@app.route('/features')
def features():
    return render_template('features.html') 