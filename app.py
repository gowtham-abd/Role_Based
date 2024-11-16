from flask import Flask, redirect, url_for, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = 'satya123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:gowtham007@localhost/role_based'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define User and Role models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    role_id = db.Column(db.Integer,db.ForeignKey('role.id'))
    role = db.relationship('Role')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_user(username, password, role_name):
    rname = username
    # Check if the role exists in the database
    db.create_all()
    if not Role.query.first():
      db.session.add_all([Role(name='admin'), Role(name='editor'), Role(name='viewer'),Role(name = "Boss")])
      db.session.commit()
    if not User.query.filter_by(username = rname ).first():        
        role =Role.query.filter_by(name=rname).first()
        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        print(f"User '{username}' with role '{role_name}' created successfully.")
        return
# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('home'))
        return "Invalid credentials"
    return render_template('login.html')

# Define role-based routes
@app.route('/')
@login_required
def home():
    return render_template('home.html', role=current_user.role.name)

@app.route('/admin')
@login_required
def admin_page():
    if current_user.role.name != 'admin':
        return "Access Denied"
    return render_template('admin.html')

@app.route('/editor')
@login_required
def editor_page():
    if current_user.role.name not in ['admin', 'editor']:
        return "Access Denied"
    return render_template('editor.html')

@app.route('/viewer')
@login_required
def viewer_page():
    return render_template('viewer.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
  with app.app_context():
    create_user("editor", "editor","editor")
    create_user("viewer","viewer","viewer")
    create_user("admin","admin", "admin")
    app.run(debug=True)
