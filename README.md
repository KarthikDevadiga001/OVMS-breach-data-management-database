# Online Vulnerability Management System (OVMS)

A comprehensive web-based system for managing and monitoring security vulnerabilities across an organization's systems. OVMS provides tools for tracking breaches, generating reports, and maintaining compliance with security policies.

## Prerequisites

- Python 3.8 or higher
- PostgreSQL 12 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/OVMS.git
cd OVMS
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/MacOS
python3 -m venv venv
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Configure PostgreSQL:
   - Install PostgreSQL if not already installed
   - Create a new database named 'OVMS'
   - Update the database connection string in `config.py` and `.env` if needed

5. Set up environment variables:
   - Create a `.env` file in the project root
   - Add the following configurations:
```
FLASK_APP=app.py
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/OVMS
```

## Database Setup

1. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

2. The system will automatically create:
   - Default admin user
   - Sample departments
   - Standard breach types
   - Initial locations

## Running the Application

1. Start the Flask development server:
```bash
flask run
```

2. Access the application at `http://localhost:5000`

## Project Structure

```
OVMS/
├── app.py              # Main application file
├── config.py           # Configuration settings
├── models.py           # Database models
├── routes.py           # Application routes
├── requirements.txt    # Python dependencies
├── static/            
│   ├── css/           # Stylesheets
│   └── js/            # JavaScript files
└── templates/          # HTML templates
```

## Features in Detail

### For Administrators
- Dashboard with overview of all breaches
- Generate comprehensive reports
- Add new cyber security professionals
- Monitor systems across departments
- View detailed breach reports

### For Cyber Professionals
- Report new security breaches
- Track and update breach status
- Monitor assigned systems
- Document breach details with CVSS scoring

## Security Features

- Role-based access control
- Password hashing
- Session management
- Input validation
- CSRF protection

## Support

For support, please open an issue in the GitHub repository or contact the development team. 