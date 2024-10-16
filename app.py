'''
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            print(f"Logged in as: {user.username}, Role: {user.role}")  # Debug line
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        print(f"Dashboard for: {session['username']}, Role: {session['role']}")  # Debug line
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    print("Logging out...")  # Debug line
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        print(f"Creating water data for user: {session['username']}")  # Debug line
        if request.method == 'POST':
            ph = request.form['ph']
            color = request.form['color']
            acidity = request.form['acidity']
            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()
            flash('Water data created successfully')
            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        print(f"Viewing water data for user: {session['username']}, Data: {water_data}")  # Debug line
        return render_template('view_water_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        print(f"Managing users, Admin: {session['username']}, Users: {users}")  # Debug line
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        print(f"Validating data, Government: {session['username']}, Data: {water_data}")  # Debug line
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate/<int:data_id>', methods=['POST'])
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)
        flash(f'Data validated successfully. User {user.username} has been incentivized.')
        db.session.commit()
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    # Handle MetaMask validation process
    data_id = request.form['data_id']
    data = WaterData.query.get_or_404(data_id)
    data.validated = True
    data.validator_id = session['user_id']
    user = User.query.get(data.user_id)
    flash(f'Data validated successfully. User {user.username} has been incentivized.')
    db.session.commit()
    return redirect(url_for('validate_data'))

@app.route('/about_us')
def about_us():
    return 'About Us Page'

@app.route('/email_us')
def email_us():
    return 'Email Us Page'

@app.route('/water_supply')
def water_supply():
    return 'Water Supply Page'

@app.route('/water_consumers')
def water_consumers():
    return 'Water Consumers Page'

@app.route('/water_treatment')
def water_treatment():
    return 'Water Treatment Page'

@app.route('/water_discharge')
def water_discharge():
    return 'Water Discharge Page'

if __name__ == '__main__':
    # Create the database tables
    with app.app_context():
        db.create_all()
    app.run(debug=True)
ANOTHER ONE 

from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        return render_template('view_water_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        db.session.commit()
        return '', 200
    return '', 403

@app.route('/validate/<int:data_id>')
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)
        flash(f'Data validated successfully. User {user.username} has been incentivized.')
        db.session.commit()
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/about_us')
def about_us():
    return 'About Us Page'

@app.route('/email_us')
def email_us():
    return 'Email Us Page'

@app.route('/water_supply')
def water_supply():
    return 'Water Supply Page'

@app.route('/water_consumers')
def water_consumers():
    return 'Water Consumers Page'

@app.route('/water_treatment')
def water_treatment():
    return 'Water Treatment Page'

@app.route('/water_discharge')
def water_discharge():
    return 'Water Discharge Page'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

    ANOTHER ONE

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

# Connect to Sepolia Test Network
sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

        # Get validator information
        validator_usernames = {}
        for data in water_data:
            if data.validator_id:
                validator = User.query.get(data.validator_id)
                if validator:
                    validator_usernames[data.validator_id] = validator.username

        return render_template('view_water_data.html', water_data=water_data, transactions=transactions, validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        db.session.commit()
        return '', 200
    return '', 403

@app.route('/validate/<int:data_id>')
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)
        
        # Create an incentive transaction
        incentive_amount = 0.00000034  # Incentive amount in ETH
        tx = {
            'to': ACCOUNT.address,
            'value': web3.toWei(incentive_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        # Add incentive transaction to database
        incentive_transaction = Transaction(user_id=user.id, transaction_type='incentive', amount=incentive_amount)
        db.session.add(incentive_transaction)
        db.session.commit()

        flash(f'Data validated successfully. User {user.username} has been incentivized. Transaction hash: {web3.toHex(tx_hash)}')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    if 'username' in session and session['role'] == 'government':
        recipient_address = request.form.get('recipient_address')
        
        penalty_amount = 0.0000057  # Penalty amount in ETH
        tx = {
            'to': recipient_address,
            'value': web3.toWei(penalty_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        
        # Add penalty transaction to database
        penalty_transaction = Transaction(user_id=session['user_id'], transaction_type='penalty', amount=penalty_amount)
        db.session.add(penalty_transaction)
        db.session.commit()

        return jsonify({'tx_hash': web3.toHex(tx_hash)})
    return '', 403

@app.route('/apply_validation', methods=['POST'])
def apply_validation():
    if 'username' in session and session['role'] == 'government':
        recipient_address = request.form.get('recipient_address')
        
        validate_amount = 0.000004  # Validation amount in ETH
        tx = {
            'to': recipient_address,
            'value': web3.toWei(validate_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        
        return jsonify({'tx_hash': web3.toHex(tx_hash)})
    return '', 403

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')

@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')

@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')

@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')


if __name__ == '__main__':
    app.run(debug=True)



from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

# Connect to Sepolia Test Network
sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

        # Get validator information
        validator_usernames = {}
        for data in water_data:
            if data.validator_id:
                validator = User.query.get(data.validator_id)
                if validator:
                    validator_usernames[data.validator_id] = validator.username

        return render_template('view_water_data.html', water_data=water_data, transactions=transactions, validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        transaction_hash = request.form.get('transaction_hash')
        amount_sent = request.form.get('amount_sent')
        amount_received = request.form.get('amount_received')

        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        data.transaction_hash = transaction_hash
        data.amount_sent = amount_sent
        data.amount_received = amount_received
        db.session.commit()
        return jsonify({'success': True})
    return '', 403

@app.route('/validate/<int:data_id>')
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)
        
        # Create an incentive transaction
        incentive_amount = 0.00000034  # Incentive amount in ETH
        tx = {
            'to': ACCOUNT.address,
            'value': web3.toWei(incentive_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        # Add incentive transaction to database
        incentive_transaction = Transaction(user_id=user.id, transaction_type='incentive', amount=incentive_amount)
        db.session.add(incentive_transaction)
        db.session.commit()

        flash(f'Data validated successfully. User {user.username} has been incentivized. Transaction hash: {web3.toHex(tx_hash)}')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    if 'username' in session and session['role'] == 'government':
        recipient_address = request.form.get('recipient_address')
        
        penalty_amount = 0.0000057  # Penalty amount in ETH
        tx = {
            'to': recipient_address,
            'value': web3.toWei(penalty_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        
        # Add penalty transaction to database
        penalty_transaction = Transaction(user_id=session['user_id'], transaction_type='penalty', amount=penalty_amount)
        db.session.add(penalty_transaction)
        db.session.commit()

        return jsonify({'tx_hash': web3.toHex(tx_hash)})
    return '', 403

@app.route('/apply_validation', methods=['POST'])
def apply_validation():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        data = WaterData.query.get(data_id)
        data.validated = True
        data.validator_id = session['user_id']

        # Add validation transaction to database
        validation_transaction = Transaction(user_id=session['user_id'], transaction_type='validation', amount=0)
        db.session.add(validation_transaction)
        db.session.commit()
        
        return redirect(url_for('validate_data'))
    return '', 403


@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')

@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')

@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')

@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')

if __name__ == '__main__':
    app.run(debug=True)

    
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet and Sepolia Test Network
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()  # Clear entire session
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

        # Get validator information
        validator_usernames = {data.validator_id: User.query.get(data.validator_id).username for data in water_data if data.validator_id}

        return render_template('view_water_data.html', water_data=water_data, transactions=transactions, validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        transaction_hash = request.form.get('transaction_hash')
        amount_sent = float(request.form.get('amount_sent', 0))
        amount_received = float(request.form.get('amount_received', 0))

        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        data.transaction_hash = transaction_hash
        data.amount_sent = amount_sent
        data.amount_received = amount_received
        db.session.commit()
        return jsonify({'success': True})
    return '', 403

@app.route('/validate/<int:data_id>')
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)

        # Ethereum account and key
        ACCOUNT = web3.eth.account.privateKeyToAccount(os.environ.get('PRIVATE_KEY'))
        
        # Create an incentive transaction
        incentive_amount = 0.00000034  # Incentive amount in ETH
        tx = {
            'to': ACCOUNT.address,
            'value': web3.toWei(incentive_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, os.environ.get('PRIVATE_KEY'))
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        # Add incentive transaction to database
        incentive_transaction = Transaction(user_id=user.id, transaction_type='incentive', amount=incentive_amount)
        db.session.add(incentive_transaction)
        db.session.commit()

        flash(f'Data validated successfully. User {user.username} has been incentivized. Transaction hash: {web3.toHex(tx_hash)}')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    if 'username' in session and session['role'] == 'government':
        recipient_address = request.form.get('recipient_address')

        # Ethereum account and key
        ACCOUNT = web3.eth.account.privateKeyToAccount(os.environ.get('PRIVATE_KEY'))

        penalty_amount = 0.0000057  # Penalty amount in ETH
        tx = {
            'to': recipient_address,
            'value': web3.toWei(penalty_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, os.environ.get('PRIVATE_KEY'))
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        penalty_transaction = Transaction(user_id=session['user_id'], transaction_type='penalty', amount=penalty_amount)
        db.session.add(penalty_transaction)
        db.session.commit()

        return jsonify({'success': True, 'tx_hash': web3.toHex(tx_hash)})

    return jsonify({'success': False, 'error': 'Unauthorized'}), 403

@app.route('/update_water_data', methods=['GET', 'POST'])
def update_water_data():
    if request.method == 'POST':
        # Handle form submission
        pass
    return render_template('update_water_data.html')


@app.route('/query_water_data')
def query_water_data():
    return render_template('query_water_data.html')

@app.route('/delete_water_data', methods=['POST'])
def delete_water_data():
    # Handle data deletion
    return redirect(url_for('dashboard'))



@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')

@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')

@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')

@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet and Sepolia Test Network
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', 
                               username=session['username'], 
                               role=session['role'])
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()  # Clear entire session
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

        # Get validator information
        validator_usernames = {data.validator_id: User.query.get(data.validator_id).username for data in water_data if data.validator_id}

        return render_template('view_water_data.html', water_data=water_data, transactions=transactions, validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    if 'username' in session and session['role'] == 'government':
        data_id = request.form.get('data_id')
        transaction_hash = request.form.get('transaction_hash')
        amount_sent = float(request.form.get('amount_sent', 0))
        amount_received = float(request.form.get('amount_received', 0))

        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        data.transaction_hash = transaction_hash
        data.amount_sent = amount_sent
        data.amount_received = amount_received
        db.session.commit()
        return jsonify({'success': True})
    return '', 403

@app.route('/validate/<int:data_id>')
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get_or_404(data_id)
        data.validated = True
        data.validator_id = session['user_id']
        user = User.query.get(data.user_id)

        # Ethereum account and key
        ACCOUNT = web3.eth.account.privateKeyToAccount(os.environ.get('PRIVATE_KEY'))
        
        # Create an incentive transaction
        incentive_amount = 0.00000034  # Incentive amount in ETH
        tx = {
            'to': ACCOUNT.address,
            'value': web3.toWei(incentive_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, os.environ.get('PRIVATE_KEY'))
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        # Add incentive transaction to database
        incentive_transaction = Transaction(user_id=user.id, transaction_type='incentive', amount=incentive_amount)
        db.session.add(incentive_transaction)
        db.session.commit()

        flash(f'Data validated successfully. User {user.username} has been incentivized. Transaction hash: {web3.toHex(tx_hash)}')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    if 'username' in session and session['role'] == 'government':
        recipient_address = request.form.get('recipient_address')

        # Ethereum account and key
        ACCOUNT = web3.eth.account.privateKeyToAccount(os.environ.get('PRIVATE_KEY'))

        penalty_amount = 0.0000057  # Penalty amount in ETH
        tx = {
            'to': recipient_address,
            'value': web3.toWei(penalty_amount, 'ether'),
            'gas': 2000000,
            'gasPrice': web3.toWei('20', 'gwei'),
            'nonce': web3.eth.getTransactionCount(ACCOUNT.address),
        }
        signed_tx = web3.eth.account.sign_transaction(tx, os.environ.get('PRIVATE_KEY'))
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

        penalty_transaction = Transaction(user_id=session['user_id'], transaction_type='penalty', amount=penalty_amount)
        db.session.add(penalty_transaction)
        db.session.commit()

        flash(f'Penalty applied successfully. Transaction hash: {web3.toHex(tx_hash)}')
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Unauthorized'}), 403

@app.route('/check_connection')
def check_connection():
    if 'username' in session:
        is_connected = web3.isConnected() and web3_sepolia.isConnected()
        mainnet_block_number = web3.eth.block_number if is_connected else 'N/A'
        sepolia_block_number = web3_sepolia.eth.block_number if is_connected else 'N/A'

        # Fetch balance
        user_address = os.environ.get('USER_ADDRESS')  # Environment variable for security
        balance_mainnet = web3.eth.get_balance(user_address) if is_connected else 0
        balance_sepolia = web3_sepolia.eth.get_balance(user_address) if is_connected else 0

        return jsonify({
            'connected': is_connected,
            'mainnet_block_number': mainnet_block_number,
            'sepolia_block_number': sepolia_block_number,
            'balance_mainnet': web3.fromWei(balance_mainnet, 'ether'),
            'balance_sepolia': web3_sepolia.fromWei(balance_sepolia, 'ether')
        })
    return '', 403

@app.route('/query_data', methods=['GET', 'POST'])
def query_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            query = request.form['query']
            results = WaterData.query.filter(WaterData.color.contains(query)).all()
            return render_template('query_results.html', results=results)
        return render_template('query_data.html')
    return redirect(url_for('login'))

@app.route('/update_water_data/<int:data_id>', methods=['GET', 'POST'])
def update_water_data(data_id):
    if 'username' in session and session['role'] == 'user':
        data = WaterData.query.get_or_404(data_id)
        if request.method == 'POST':
            data.ph = float(request.form['ph'])
            data.color = request.form['color']
            data.acidity = float(request.form['acidity'])
            db.session.commit()
            flash('Data updated successfully.')
            return redirect(url_for('view_water_data'))
        return render_template('update_water_data.html', data=data)
    return redirect(url_for('login'))


@app.route('/delete_water_data/<int:data_id>', methods=['POST'])
def delete_water_data(data_id):
    if 'username' in session and session['role'] == 'user':
        data = WaterData.query.get_or_404(data_id)
        db.session.delete(data)
        db.session.commit()
        flash('Data deleted successfully.')
        return redirect(url_for('view_water_data'))
    return redirect(url_for('login'))

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')

@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')

@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')

@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')


if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet and Sepolia Test Network
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        items = WaterData.query.all()  # Fetch water data items
        return render_template(
            'dashboard.html',
            username=session['username'],
            role=session['role'],
            items=items  # Pass items to the template
        )
    return redirect(url_for('login'))



@app.route('/logout')
def logout():
    session.clear()  # Clear entire session
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

        # Get validator information
        validator_usernames = {data.validator_id: User.query.get(data.validator_id).username for data in water_data if data.validator_id}

        return render_template('view_water_data.html', water_data=water_data, transactions=transactions, validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data and not data.validated:
        # MetaMask validation logic
        transaction_hash = "0x..."  # Replace with actual transaction hash
        data.validated = True
        data.transaction_hash = transaction_hash
        db.session.commit()

        flash('Data validated successfully!')
    return redirect(url_for('validate_data'))

@app.route('/validate/<int:data_id>', methods=['POST'])
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get(data_id)
        if data and not data.validated:
            data.validated = True
            db.session.commit()
            flash('Data validated successfully!')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))

@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data:
        user = User.query.get(data.user_id)
        # Logic for applying penalty
        flash('Penalty applied successfully!')
    return redirect(url_for('validate_data'))

@app.route('/check_connection')
def check_connection():
    connection_status = web3.isConnected()
    block_number = web3.eth.blockNumber
    balance = web3.eth.getBalance("0xYourAddress")  # Replace with actual address
    return jsonify({'connection_status': connection_status, 'block_number': block_number, 'balance': balance})

@app.route('/query_data', methods=['GET'])
def query_data():
    if 'username' in session and session['role'] == 'user':
        query = request.args.get('query')
        water_data = WaterData.query.filter(WaterData.ph.contains(query) | WaterData.color.contains(query)).all()
        return render_template('query_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/update_water_data/<int:data_id>', methods=['GET', 'POST'])
def update_water_data(data_id):
    if 'username' in session and session['role'] == 'user':
        data = WaterData.query.get_or_404(data_id)
        if request.method == 'POST':
            data.ph = float(request.form['ph'])
            data.color = request.form['color']
            data.acidity = float(request.form['acidity'])
            db.session.commit()
            flash('Data updated successfully.')
            return redirect(url_for('view_water_data'))
        return render_template('update_water_data.html', data=data)
    return redirect(url_for('login'))



@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')

@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')

@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')

@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet and Sepolia Test Network
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        items = WaterData.query.all()  # Fetch water data items
        return render_template(
            'dashboard.html',
            username=session['username'],
            role=session['role'],
            items=items  # Pass items to the template
        )
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()  # Clear entire session
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
        # Get validator information
        validator_usernames = {data.validator_id: User.query.get(data.validator_id).username for data in water_data if
                               data.validator_id}
        return render_template('view_water_data.html', water_data=water_data, transactions=transactions,
                               validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data and not data.validated:
        # MetaMask validation logic
        transaction_hash = "0x..."  # Replace with actual transaction hash
        data.validated = True
        data.transaction_hash = transaction_hash
        db.session.commit()

        flash('Data validated successfully!')
    return redirect(url_for('validate_data'))

@app.route('/validate/<int:data_id>', methods=['POST'])
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get(data_id)
        if data and not data.validated:
            data.validated = True
            db.session.commit()
            flash('Data validated successfully!')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))


@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data:
        user = User.query.get(data.user_id)
        # Logic for applying penalty
        flash('Penalty applied successfully!')
    return redirect(url_for('validate_data'))


@app.route('/check_connection')
def check_connection():
    connection_status = web3.isConnected()
    block_number = web3.eth.blockNumber
    balance = web3.eth.getBalance("0x776A1E56d80feC35C7b16476116C4257e061C223")  # Replace with actual address
    return jsonify({'connection_status': connection_status, 'block_number': block_number, 'balance': balance})

@app.route('/query_data', methods=['GET'])
def query_data():
    if 'username' in session and session['role'] == 'user':
        query = request.args.get('query')
        # If query is None or empty, return an empty list or handle appropriately
        if not query:
            water_data = []  # Return an empty list if no query is provided
        else:
            # Query water data where ph or color contains the query string
            water_data = WaterData.query.filter(
                WaterData.ph.contains(query) | WaterData.color.contains(query)
            ).all()
        return render_template('query_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/update_water_data/<int:data_id>', methods=['GET', 'POST'])
def update_water_data(data_id):
    if 'username' in session and session['role'] == 'user':
        data = WaterData.query.get_or_404(data_id)
        if request.method == 'POST':
            data.ph = float(request.form['ph'])
            data.color = request.form['color']
            data.acidity = float(request.form['acidity'])
            db.session.commit()
            flash('Data updated successfully.')
            return redirect(url_for('view_water_data'))
        return render_template('update_water_data.html', data=data)
    return redirect(url_for('login'))


@app.route('/about_us')
def about_us():
    return render_template('about_us.html')


@app.route('/email_us')
def email_us():
    return render_template('email_us.html')


@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')


@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')


@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
'''

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from web3 import Web3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_quality.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Connect to Ethereum Mainnet and Sepolia Test Network
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/3OqltayCdWx7230AEE3WNjtBp-xdAqoN"
web3 = Web3(Web3.HTTPProvider(alchemy_url))

sepolia_rpc_url = "https://sepolia-testnet-rpc.com"
web3_sepolia = Web3(Web3.HTTPProvider(sepolia_rpc_url))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class WaterData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ph = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(100), nullable=False)
    acidity = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validated = db.Column(db.Boolean, default=False)
    validator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(100), nullable=True)
    amount_sent = db.Column(db.Float, nullable=True)
    amount_received = db.Column(db.Float, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        items = WaterData.query.all()  # Fetch water data items
        return render_template(
            'dashboard.html',
            username=session['username'],
            role=session['role'],
            items=items  # Pass items to the template
        )
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()  # Clear entire session
    return redirect(url_for('login'))

@app.route('/create_water_data', methods=['GET', 'POST'])
def create_water_data():
    if 'username' in session and session['role'] == 'user':
        if request.method == 'POST':
            ph = float(request.form['ph'])
            color = request.form['color']
            acidity = float(request.form['acidity'])
            negative_values = ph < 0 or acidity < 0

            new_data = WaterData(ph=ph, color=color, acidity=acidity, user_id=session['user_id'])
            db.session.add(new_data)
            db.session.commit()

            if negative_values:
                flash('Data created with negative values. You will need to pay a penalty if validated.')
            else:
                flash('Data created successfully. Awaiting validation.')

            return redirect(url_for('dashboard'))
        return render_template('create_water_data.html')
    return redirect(url_for('login'))

@app.route('/view_water_data')
def view_water_data():
    if 'username' in session and session['role'] == 'user':
        water_data = WaterData.query.filter_by(user_id=session['user_id']).all()
        transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
        # Get validator information
        validator_usernames = {data.validator_id: User.query.get(data.validator_id).username for data in water_data if
                               data.validator_id}
        return render_template('view_water_data.html', water_data=water_data, transactions=transactions,
                               validator_usernames=validator_usernames)
    return redirect(url_for('login'))

@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('manage_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/validate_data')
def validate_data():
    if 'username' in session and session['role'] == 'government':
        water_data = WaterData.query.filter_by(validated=False).all()
        return render_template('validate_data.html', water_data=water_data)
    return redirect(url_for('login'))


@app.route('/validate_with_metamask', methods=['POST'])
def validate_with_metamask():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data and not data.validated:
        # MetaMask validation logic here
        transaction_hash = "0x2f09f4d270762b0bdf96998264cdaab5e326aa36fbf83d2630e206e100f5accb"  # Replace with actual transaction hash
        data.validated = True
        data.transaction_hash = transaction_hash
        data.validator_id = session.get('user_id')  # Set the current user as the validator
        db.session.commit()

        flash('Data validated successfully!')
    return redirect(url_for('validate_data'))


@app.route('/validate/<int:data_id>', methods=['POST'])
def validate(data_id):
    if 'username' in session and session['role'] == 'government':
        data = WaterData.query.get(data_id)
        if data and not data.validated:
            data.validated = True
            data.validator_id = session.get('user_id')  # Set the current user as the validator
            db.session.commit()
            flash('Data validated successfully!')
        return redirect(url_for('validate_data'))
    return redirect(url_for('login'))


@app.route('/apply_penalty', methods=['POST'])
def apply_penalty():
    data_id = request.form['data_id']
    data = WaterData.query.get(data_id)
    if data:
        user = User.query.get(data.user_id)
        # Logic for applying penalty
        flash('Penalty applied successfully!')
    return redirect(url_for('validate_data'))

@app.route('/check_connection')
def check_connection():
    connection_status = web3.isConnected()
    block_number = web3.eth.blockNumber
    balance = web3.eth.getBalance("0x776A1E56d80feC35C7b16476116C4257e061C223")  
    return jsonify({'connection_status': connection_status, 'block_number': block_number, 'balance': balance})

@app.route('/query_data', methods=['GET'])
def query_data():
    if 'username' in session and session['role'] == 'user':
        query = request.args.get('query')
        # If query is None or empty, return an empty list or handle appropriately
        if not query:
            water_data = []  # Return an empty list if no query is provided
        else:
            # Query water data where ph or color contains the query string
            water_data = WaterData.query.filter(
                WaterData.ph.contains(query) | WaterData.color.contains(query)
            ).all()
        return render_template('query_data.html', water_data=water_data)
    return redirect(url_for('login'))

@app.route('/update_water_data/<int:data_id>', methods=['GET', 'POST'])
def update_water_data(data_id):
    if 'username' in session and session['role'] == 'user':
        data = WaterData.query.get_or_404(data_id)
        if request.method == 'POST':
            data.ph = float(request.form['ph'])
            data.color = request.form['color']
            data.acidity = float(request.form['acidity'])
            db.session.commit()
            flash('Data updated successfully.')
            return redirect(url_for('view_water_data'))
        return render_template('update_water_data.html', data=data)
    return redirect(url_for('login'))

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/email_us')
def email_us():
    return render_template('email_us.html')


@app.route('/water_supply')
def water_supply():
    return render_template('water_supply.html')


@app.route('/water_demand')
def water_demand():
    return render_template('water_demand.html')


@app.route('/water_consumers')
def water_consumers():
    return render_template('water_consumers.html')

@app.route('/water_treatment')
def water_treatment():
    return render_template('water_treatment.html')

@app.route('/water_discharge')
def water_discharge():
    return render_template('water_discharge.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)

    