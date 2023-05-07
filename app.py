# Import libraries
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import json
import base64

# Run Flask app
app = Flask(__name__, static_url_path='/static')

# Configure database and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'some_secret_key'

# Run database and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Set up login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    vt_api_key = db.Column(db.String(120), nullable=False)
    ibm_api_key = db.Column(db.String(120), nullable=False)
    ipapi_api_key = db.Column(db.String(120), nullable=False)
    abuseipdb_api_key = db.Column(db.String(120), nullable=False)

# Load user 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get user information from form
        username = request.form['username']
        password = request.form['password']
        vt_api_key = request.form['vt_api_key']
        ibm_api_key = request.form['ibm_api_key']
        ipapi_api_key = request.form['ipapi_api_key']
        abuseipdb_api_key = request.form['abuseipdb_api_key']

        # Create new user and add to the database
        new_user = User(username=username, password=password, vt_api_key=vt_api_key, ibm_api_key=ibm_api_key,
                        ipapi_api_key=ipapi_api_key, abuseipdb_api_key=abuseipdb_api_key)

        db.session.add(new_user)
        db.session.commit()

        # Redirect to login page after successful signup
        return redirect(url_for('login'))

    # Render the signup page
    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user credentials from form
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct, then log in the user
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('home', user_id=user.id))
        else:
            # Show error message if credentials are incorrect
            flash('Invalid credentials. Please try again.')

    # Render the login page
    return render_template('login.html')

# Home route
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Main index route
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    # Get user information
    user_id = request.args.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    
    if user:
        # Get user API keys
        vt_api_key = user.vt_api_key
        ibm_api_key = user.ibm_api_key
        ipapi_api_key = user.ipapi_api_key
        abuseipdb_api_key = user.abuseipdb_api_key
    else:
        # Redirect to login if user is not found
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))

    # Initialize variables for API data
    vt_malicious_score = None
    xfe_score = None
    country = None
    isp = None
    abuseipdb_score = None

    if request.method == 'POST':
        # Get IP address from form
        ip_address = request.form['ip_address']

        # VirusTotal API call
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        vt_malicious_score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        isp = data["data"]["attributes"]["as_owner"]

        # IBM X-Force Exchange API call
        xfe_url = f"https://api.xforce.ibmcloud.com/ipr/{ip_address}"
        encoded_key = base64.b64encode(ibm_api_key.encode()).decode()
        xfe_headers = {"Accept": "application/json", "Authorization": f"Basic {encoded_key}"}
        xfe_response = requests.get(xfe_url, headers=xfe_headers)
        xfe_data = json.loads(xfe_response.text)
        xfe_score = xfe_data.get("score")

        # IP Geolocation API call
        ip_api_url = f"http://api.ipapi.com/{ip_address}?access_key={ipapi_api_key}&fields=country_name"
        ip_api_response = requests.get(ip_api_url)
        ip_api_data = json.loads(ip_api_response.text)
        country = ip_api_data.get('country_name', 'Unknown')

        # AbuseIPDB API call
        abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
        abuseipdb_headers = {"Accept": "application/json", "Key": abuseipdb_api_key}
        abuseipdb_response = requests.get(abuseipdb_url, headers=abuseipdb_headers)
        abuseipdb_data = json.loads(abuseipdb_response.text)
        abuseipdb_score = abuseipdb_data.get("data").get("abuseConfidenceScore")

    # Render the index page with API data
    return render_template('index.html', vt_malicious_score=vt_malicious_score, xfe_score=xfe_score, country=country, isp=isp, abuseipdb_score=abuseipdb_score)

# Filehash route
@app.route('/filehash', methods=['GET', 'POST'])
@login_required
def filehash():
    # Get user information
    user_id = request.args.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    
    if user:
        # Get user API keys
        vt_api_key = user.vt_api_key
        ibm_api_key = user.ibm_api_key
    else:
        # Redirect to login if user is not found
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))

    # Initialize variables for API data
    vt_malicious_score = None
    xfe_score = None

    if request.method == 'POST':
        # Get file hash from form
        file_hash = request.form['file_hash']

        # VirusTotal API call
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        vt_malicious_score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

        # IBM X-Force Exchange API call
        xfe_url = f"https://api.xforce.ibmcloud.com/malware/{file_hash}"
        encoded_key = base64.b64encode(ibm_api_key.encode()).decode()
        xfe_headers = {"Accept": "application/json", "Authorization": f"Basic {encoded_key}"}
        xfe_response = requests.get(xfe_url, headers=xfe_headers)
        xfe_data = json.loads(xfe_response.text)
        xfe_score = xfe_data.get("malware", {}).get("risk")

    # Render the filehash page with API data
    return render_template('filehash.html', vt_malicious_score=vt_malicious_score, xfe_score=xfe_score)

# Run the app
if __name__ == '__main__':
    app.run(debug=True, port=5000, host='127.0.0.1')



