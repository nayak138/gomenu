from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    restaurant = db.relationship('Restaurant', backref='owner', lazy=True)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    logo_url = db.Column(db.String(200))
    google_reviews = db.Column(db.String(200))
    google_location = db.Column(db.String(200))
    instagram = db.Column(db.String(200))
    whatsapp = db.Column(db.String(200))
    facebook = db.Column(db.String(200))
    zomato_link = db.Column(db.String(200))
    swiggy_link = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    categories = db.relationship('Category', backref='restaurant', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    items = db.relationship('MenuItem', backref='category', lazy=True)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.String(20), nullable=False)
    image_url = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.is_admin else 'owner_dashboard'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/')
def home():
    restaurants = Restaurant.query.all()
    return render_template('index.html', restaurants=restaurants)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.filter_by(is_admin=False).all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/add_owner', methods=['GET', 'POST'])
@login_required
def add_owner():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        restaurant_name = request.form.get('restaurant_name')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        owner = User(email=email, password=hashed_password, is_admin=False)
        db.session.add(owner)
        db.session.flush()

        restaurant = Restaurant(name=restaurant_name, owner_id=owner.id)
        db.session.add(restaurant)
        db.session.commit()

        return redirect(url_for('admin_dashboard'))

    return render_template('add_owner.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.email = request.form.get('email')
        if request.form.get('password'):
            user.password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')

        restaurant = user.restaurant[0] if user.restaurant else Restaurant(owner_id=user.id)
        restaurant.name = request.form.get('restaurant_name')
        if not user.restaurant:
            db.session.add(restaurant)

        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_owner.html', user=user)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get_or_404(id)
    if user.restaurant:
        db.session.delete(user.restaurant[0])
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/restaurant/<int:id>')
def restaurant_menu(id):
    restaurant = Restaurant.query.get_or_404(id)
    return render_template('restaurant_menu.html', restaurant=restaurant)

@app.route('/owner/dashboard')
@login_required
def owner_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('owner_dashboard.html', restaurant=current_user.restaurant[0])

@app.route('/update-restaurant', methods=['POST'])
@login_required
def update_restaurant():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    restaurant = current_user.restaurant[0]
    restaurant.name = request.form.get('name')
    restaurant.description = request.form.get('description')
    
    if 'logo' in request.files:
        logo = request.files['logo']
        if logo.filename:
            # Save the uploaded file
            filename = f'uploads/{secure_filename(logo.filename)}'
            logo.save(os.path.join('static', filename))
            restaurant.logo_url = filename
    restaurant.google_reviews = request.form.get('google_reviews')
    restaurant.google_location = request.form.get('google_location')
    restaurant.instagram = request.form.get('instagram')
    restaurant.whatsapp = request.form.get('whatsapp')
    restaurant.facebook = request.form.get('facebook')
    restaurant.zomato_link = request.form.get('zomato_link')
    restaurant.swiggy_link = request.form.get('swiggy_link')
    restaurant.phone = request.form.get('phone')

    db.session.commit()
    return redirect(url_for('owner_dashboard'))

@app.route('/add-category', methods=['POST'])
@login_required
def add_category():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    name = request.form.get('name')
    category = Category(name=name, restaurant_id=current_user.restaurant[0].id)
    db.session.add(category)
    db.session.commit()
    return redirect(url_for('owner_dashboard'))

@app.route('/add-item/<int:category_id>', methods=['GET', 'POST'])
@login_required
def add_item(category_id):
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    category = Category.query.get_or_404(category_id)
    if category.restaurant.owner != current_user:
        return redirect(url_for('owner_dashboard'))

    if request.method == 'POST':
        item = MenuItem(
            name=request.form.get('name'),
            description=request.form.get('description'),
            price=request.form.get('price'),
            category_id=category_id
        )
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename:
                item.image_url = image.filename
                image.save(f'static/uploads/{image.filename}')
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('owner_dashboard'))

    return render_template('add_item.html')

@app.route('/edit-item/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    item = MenuItem.query.get_or_404(id)
    if not current_user.is_admin and item.category.restaurant.owner != current_user:
        return redirect(url_for('owner_dashboard'))

    if request.method == 'POST':
        item.name = request.form.get('name')
        item.description = request.form.get('description')
        item.price = float(request.form.get('price'))
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename:
                item.image_url = image.filename
                image.save(f'static/uploads/{image.filename}')
        db.session.commit()
        return redirect(url_for('owner_dashboard'))

    return render_template('edit_item.html', item=item)

@app.route('/delete-item/<int:id>')
@login_required
def delete_item(id):
    item = MenuItem.query.get_or_404(id)
    if current_user.is_admin or item.category.restaurant.owner != current_user:
        return redirect(url_for('owner_dashboard'))

    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('owner_dashboard'))

@app.before_first_request
def initialize_database():
    db.create_all()
    # Create admin user if it doesn't exist
    admin_email = "admin@example.com"
    if not User.query.filter_by(email=admin_email).first():
        hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
        admin = User(email=admin_email, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user created with email: {admin_email} and password: admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        admin_email = "admin@example.com"
        if not User.query.filter_by(email=admin_email).first():
            hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
            admin = User(email=admin_email, password=hashed_password, is_admin=True)
            db.session.add(admin)
            db.session.commit()
    
    # Development mode
    if not os.environ.get('REPL_SLUG'):
        app.run(host='0.0.0.0', port=5000, debug=True)
    # Production mode
    else:
        app.run(host='0.0.0.0', port=5000)