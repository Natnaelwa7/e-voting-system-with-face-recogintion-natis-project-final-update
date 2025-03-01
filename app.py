from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify, json,session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from sqlalchemy import UniqueConstraint
from sqlalchemy import func
import uuid
import base64
from datetime import datetime, timezone
import time
import re
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_login import UserMixin
from scipy.spatial.distance import cosine
import cv2
import numpy as np
from flask_sqlalchemy import SQLAlchemy
from deepface import DeepFace
from dotenv import load_dotenv
import logging
utc_now = datetime.fromtimestamp(time.time(), tz=timezone.utc)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evoting.db'
app.config['SECRET_KEY'] = secrets.token_hex(16)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

class Voter(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facial_data = db.Column(db.Text, nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'))
    role = db.Column(db.String(50), default='voter')  # New field

class ElectionOfficer(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    blocked = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='eadmin')  # New field

class SystemAdmin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='sysadmin')  # New field
class Election(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(255))
    
    # Relationships
    parties = db.relationship('Party', backref='election', lazy=True)
    candidates = db.relationship('Candidate', backref='election', lazy=True)
    voters = db.relationship('Voter', backref='election', lazy=True) 
    

class Party(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=True)  # Optional association

    # Relationship to Candidates
    candidates = db.relationship('Candidate', backref='party', lazy=True)  # Add this line
class Candidate(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party_id = db.Column(db.Integer, db.ForeignKey('party.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes = db.Column(db.Integer, default=0)
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), unique=True, nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    voter = db.relationship('Voter', backref=db.backref('vote', uselist=False))
    candidate = db.relationship('Candidate', backref='votes_received')
    election = db.relationship('Election', backref='votes_cast')













@property
def is_active(self):
        now = datetime.now()
        return self.start_time <= now <= self.end_time
@login_manager.user_loader
def load_user(user_id):
    for model in [Voter, ElectionOfficer, SystemAdmin]:
        user = model.query.get(int(user_id))  # Ensure user_id is converted to int
        if user:
            return user
    return None
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Check all user types to find the correct one
    voter = Voter.query.get(user_id)
    if voter:
        return voter

    officer = ElectionOfficer.query.get(user_id)
    if officer:
        return officer

    admin = SystemAdmin.query.get(user_id)
    if admin:
        return admin

    return None
class User(UserMixin):
    pass
# Routes for System Admin
@app.route('/sysadmin/register', methods=['GET', 'POST'])
def sysadmin_register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if not name or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('sysadmin_register'))

        existing_admin = SystemAdmin.query.filter_by(email=email).first()
        if existing_admin:
            flash('Email already registered!', 'warning')
            return redirect(url_for('sysadmin_register'))

        hashed_password = generate_password_hash(password)
        new_admin = SystemAdmin(name=name, email=email, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        flash('System Admin registered successfully!', 'success')
        return redirect(url_for('sysadmin_login'))
    
    return render_template('sysadmin_register.html')



@app.route('/delete_officer/<int:officer_id>', methods=['POST'])
def delete_officer(officer_id):
    officer = ElectionOfficer.query.get_or_404(officer_id)
    db.session.delete(officer)
    db.session.commit()
    flash(f'Officer {officer.name} has been deleted.', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/sysadmin/login', methods=['GET', 'POST'])
def sysadmin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        admin = SystemAdmin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            login_user(admin)
            flash('Login successful!', 'success')
            return redirect(url_for('sysadmin_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('sysadmin_login.html')

@app.route('/sysadmin/dashboard')
@login_required
def sysadmin_dashboard():
    voters = Voter.query.all()
    officers = ElectionOfficer.query.all()
    admins = SystemAdmin.query.all()
    return render_template('sysadmin_dashboard.html', voters=voters, officers=officers, admins=admins)

@app.route('/sysadmin/delete_voter/<int:voter_id>', methods=['POST'])
@login_required
def delete_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        db.session.delete(voter)
        db.session.commit()
        flash('Voter deleted successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))
@app.route('/sysadmin/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
def delete_admin(admin_id):
    admin = SystemAdmin.query.get(admin_id)  # Assuming you have an Admin model
    if admin:
        db.session.delete(admin)
        db.session.commit()
        flash('Admin deleted successfully', 'success')

    return redirect(url_for('sysadmin_dashboard'))
@app.route('/block_officer/<int:officer_id>', methods=['POST'])
def block_officer(officer_id):
    officer = ElectionOfficer.query.get_or_404(officer_id)
    officer.blocked = True
    db.session.commit()
    flash(f'Officer {officer.name} has been blocked.', 'success')
    return redirect(url_for('sysadmin_dashboard'))
@app.route('/eadmin/add_party', methods=['GET', 'POST'])
@login_required
def add_party():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Party name cannot be empty!', 'danger')
            return redirect(url_for('add_party'))

        new_party = Party(name=name)
        db.session.add(new_party)
        db.session.commit()
        flash(f'Party "{name}" added successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))

    return render_template('add_party.html')


@app.route('/sysadmin/block_voter/<int:voter_id>', methods=['POST'])
@login_required
def block_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = True
        db.session.commit()
        flash('Voter blocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/sysadmin/unblock_voter/<int:voter_id>', methods=['POST'])
@login_required
def unblock_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = False
        db.session.commit()
        flash('Voter unblocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))

# Routes for Election Officer (renamed to eadmin)
@app.route('/eadmin/register', methods=['GET', 'POST'])
def eadmin_register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if not name or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('eadmin_register'))

        existing_officer = ElectionOfficer.query.filter_by(email=email).first()
        if existing_officer:
            flash('Email already registered!', 'warning')
            return redirect(url_for('eadmin_register'))

        hashed_password = generate_password_hash(password)
        new_officer = ElectionOfficer(name=name, email=email, password=hashed_password)
        db.session.add(new_officer)
        db.session.commit()
        flash('Election Officer registered successfully!', 'success')
        return redirect(url_for('eadmin_login'))
    
    return render_template('eadmin_register.html')
@app.route('/eadmin/login', methods=['GET', 'POST'])
def eadmin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        # Query the user by email
        officer = ElectionOfficer.query.filter_by(email=email).first()

        if officer and check_password_hash(officer.password, password) and officer.role == 'eadmin':
            login_user(officer)
            flash('Login successful!', 'success')
            return redirect(url_for('eadmin_dashboard'))  # Redirect to eadmin dashboard
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('eadmin_login.html')

@app.route('/eadmin/dashboard')
@login_required
def eadmin_dashboard():
    voters = Voter.query.all()
    candidates = Candidate.query.all()
    elections = Election.query.all()
    return render_template('eadmin_dashboard.html', voters=voters, candidates=candidates, elections=elections)

@app.route('/eadmin/add_election', methods=['GET', 'POST'])
@login_required
def add_election():
    if request.method == 'POST':
        name = request.form['name'].strip()
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        description = request.form['description'].strip()
        selected_parties = request.form.getlist('parties')  # Get selected parties

        if not name or not start_time or not end_time:
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_election'))

        # Convert string to datetime
        start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')

        new_election = Election(name=name, start_time=start_time, end_time=end_time, description=description)
        db.session.add(new_election)

        # Add parties to the election
        for party_id in selected_parties:
            party = Party.query.get(party_id)
            new_election.parties.append(party)

        db.session.commit()
        flash(f'Election "{name}" created successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))
    
    parties = Party.query.all()  # Fetch all parties to display in the form
    return render_template('add_election.html', parties=parties)
@app.route('/add_candidate', methods=['GET', 'POST'])
def add_candidate():
    if request.method == 'POST':
        name = request.form.get('name')
        party_id = request.form.get('party_id')
        election_id = request.form.get('election_id')

        if not party_id or not election_id:
            flash('Party and Election must be selected.', 'error')
            return redirect(url_for('add_candidate'))

        new_candidate = Candidate(name=name, votes=0, party_id=party_id, election_id=election_id)

        db.session.add(new_candidate)
        db.session.commit()
        flash('Candidate added successfully!', 'success')
        return redirect(url_for('candidates_list'))

    # Retrieve parties and elections from the database
    parties = Party.query.all()  # Assuming you have a Party model
    elections = Election.query.all()  # Assuming you have an Election model

    return render_template('add_candidate.html', parties=parties, elections=elections)  # Pass data to template



# Main Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.json
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            image_data = data.get('image', '').split(',')[1] if data.get('image') else None
            
            if not (name and email and password and image_data):
                return jsonify({'success': False, 'message': 'All fields are required'}), 400
            
            # Hash password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            # Check if email is already registered
            existing_voter = Voter.query.filter_by(email=email).first()
            if existing_voter:
                return jsonify({'success': False, 'message': 'Email already registered'}), 400

            # Save image temporarily
            filename = f"temp_{uuid.uuid4()}.jpg"
            with open(filename, 'wb') as f:
                f.write(base64.b64decode(image_data))

            # Extract facial embedding
            img = cv2.imread(filename)
            if img is None:
                os.remove(filename)
                return jsonify({'success': False, 'message': 'Invalid image format'}), 400

            embedding_data = DeepFace.represent(img, model_name='Facenet')

            if not embedding_data:
                os.remove(filename)
                return jsonify({'success': False, 'message': 'Face not detected'}), 400

            embedding = embedding_data[0]["embedding"]
            os.remove(filename)

            # Store voter in database
            new_voter = Voter(
                name=name,
                email=email,
                password=hashed_password,
                facial_data=json.dumps(embedding)  # Store embedding as JSON
            )
            db.session.add(new_voter)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Registration successful! Please log in.'}), 201
        
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred during registration'}), 500

    return render_template('register.html')
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        image_data = data.get('image')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400
        
        user = Voter.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 400
        
        if not check_password_hash(user.password, password):
            return jsonify({'success': False, 'message': 'Incorrect password'}), 400
        
        if image_data:
            try:
                image_data = image_data.split(',')[1]
                filename = f"temp_{uuid.uuid4()}.jpg"
                with open(filename, 'wb') as f:
                    f.write(base64.b64decode(image_data))
                
                img = cv2.imread(filename)
                if img is None:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid image'}), 400
                
                embeddings = DeepFace.represent(img, model_name='Facenet')
                current_embedding = embeddings[0]["embedding"]
                stored_embedding = eval(user.facial_data)
                
                distance = np.linalg.norm(np.array(current_embedding) - np.array(stored_embedding))
                os.remove(filename)
                
                if distance < 10:
                    login_user(user)  # <-- This logs in the user
                    return jsonify({
                        'success': True,
                        'redirect': url_for('vote', voter_id=user.id),
                        'message': f'Welcome, {user.name}!'
                    })
                
                return jsonify({'success': False, 'message': 'Face not recognized'}), 400
                
            except Exception as e:
                logging.error(f"Face error: {str(e)}")
                return jsonify({'success': False, 'message': 'Face verification failed'}), 400
        
        return jsonify({'success': False, 'message': 'Image required'}), 400

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal error'}), 500



@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    # Ensure proper datetime handling with timezone awareness
    current_time = datetime.now(timezone.utc)  

    # Fetch active election
    election = Election.query.filter(
        Election.start_time <= current_time,
        Election.end_time >= current_time
    ).first()

    if not election:
        flash("No active election available!", "warning")
        return redirect(url_for('home'))

    # Fetch voter information
    voter = Voter.query.get(current_user.id)
    if not voter:
        flash("Voter not found!", "danger")
        return redirect(url_for('home'))
    
    # Check if the user has already voted
    existing_vote = Vote.query.filter_by(voter_id=current_user.id, election_id=election.id).first()
    if existing_vote:
        flash("You've already cast your vote!", "danger")
        return redirect(url_for('results'))

    # Get candidates for the active election
    candidates = Candidate.query.filter_by(election_id=election.id).all()
    if not candidates:
        flash("No candidates available for this election!", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        candidate_id = request.form.get('candidate')
        candidate = Candidate.query.get(candidate_id)
        
        # Validate candidate selection
        if not candidate or candidate.election_id != election.id:
            flash("Invalid candidate selection!", "danger")
            return redirect(url_for('vote'))

        # Record the vote
        new_vote = Vote(
            voter_id=current_user.id,
            candidate_id=candidate.id,
            election_id=election.id,
            timestamp=current_time  # Maintain timezone consistency
        )
        
        try:
            # Save the vote
            db.session.add(new_vote)
            db.session.commit()
            flash("Vote successfully cast!", "success")
            return redirect(url_for('results'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error casting vote: {str(e)}", "danger")
        
        return redirect(url_for('home'))

    return render_template('vote.html', candidates=candidates, election=election)

@app.route('/get_parties/<int:election_id>')
@login_required
def get_parties(election_id):
    election = Election.query.get_or_404(election_id)
    parties = [{'id': party.id, 'name': party.name} for party in election.parties]
    return jsonify({'parties': parties})
from sqlalchemy.orm import joinedload

@app.route('/candidates_list', methods=['GET', 'POST'])
def candidates_list():
    if request.method == 'POST':
        candidate_name = request.form['candidate_name']
        party_id = request.form['party_id']
        election_id = request.form['election_id']

        new_candidate = Candidate(name=candidate_name, party_id=party_id, election_id=election_id)
        db.session.add(new_candidate)
        db.session.commit()

        return redirect(url_for('candidates_list'))

    # Eager load party and election to avoid N+1 queries and ensure all candidates are included
    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()

    parties = Party.query.all()
    elections = Election.query.all()

    return render_template('candidates_list.html', candidates=candidates, parties=parties, elections=elections)

@app.route('/results', methods=['GET'])
def results():
    # Eager load candidates, parties, and elections to avoid N+1 queries
    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()

    # Retrieve election results by candidate and party
    results = {}
    for candidate in candidates:
        party_name = candidate.party.name if candidate.party else "No Party"
        election_name = candidate.election.name if candidate.election else "No Election"
        
        # Initialize election results if not present
        if election_name not in results:
            results[election_name] = {}

        # Initialize party results if not present
        if party_name not in results[election_name]:
            results[election_name][party_name] = {
                "party_votes": 0,
                "candidates": []
            }

        # Count the total votes for each candidate
        total_votes = Vote.query.filter_by(candidate_id=candidate.id).count()

        # Add the candidate to the results with their vote count
        results[election_name][party_name]["candidates"].append({
            "candidate_name": candidate.name,
            "votes": total_votes
        })

        # Sum up the total votes for the party in this election
        results[election_name][party_name]["party_votes"] += total_votes

    return render_template('results.html', results=results)







if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)