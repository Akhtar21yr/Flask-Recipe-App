from functools import wraps
import re
from flask import Flask, render_template, request, redirect, url_for,flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import FileField, StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from datetime import datetime
import pytz
from sqlalchemy.orm import validates
from werkzeug.security import generate_password_hash , check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate

# Flask application setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) 
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# User model with email validation
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean,default = False)

    def __repr__(self):
        return f"<User {self.fullname}>"

    @validates('email')
    def validate_email(self, key, email):
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            raise ValueError("Invalid email format")
        return email


class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    recipe_name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    posted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fvrt_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    category = db.Column(db.String(50), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Kolkata')), nullable=False)

    # New column for storing image filename
    image = db.Column(db.String(120), nullable=True)

    # Correct relationships
    posted_by = db.relationship("User", backref="posted_recipes", foreign_keys=[posted_by_id])
    fvrt_by = db.relationship("User", backref="favorite_recipes", foreign_keys=[fvrt_by_id])

    def __repr__(self):
        return f"<Recipe {self.recipe_name}>"



class RegistrationForm(FlaskForm):
    fullname = StringField("Full Name", validators=[DataRequired(),Length(min=3)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField("Register")



class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class RecipeForm(FlaskForm):
    recipe_name = StringField("Recipe Name", validators=[DataRequired(), Length(min=2, max=100)])
    title = StringField("Title", validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField("Description", validators=[DataRequired(), Length(max=1000)])  # Required field
    image = FileField("Recipe Image", validators=[FileAllowed(['jpg', 'jpeg', 'png'], "Only images are allowed")])
    category = StringField("Category", validators=[DataRequired(), Length(max=50)])  # Required field
    submit = SubmitField("Save")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  
            flash("Login required", "danger")  
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs) 
    return decorated_function


@app.route('/')
def home():
    # Fetch all recipes from the database, ordered by latest
    recipes = Recipe.query.order_by(Recipe.category.asc()).all()  # Ordered by latest

    # Group recipes by category if needed
    recipes_by_category = {}
    for recipe in recipes:
        category = recipe.category if recipe.category else "Uncategorized"
        if category not in recipes_by_category:
            recipes_by_category[category] = []
        recipes_by_category[category].append(recipe)

    return render_template('home.html', recipes_by_category=recipes_by_category)



# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():  # Check if the form is valid and submitted
        fullname = form.fullname.data
        email = form.email.data
        password = form.password.data

        # Check if email is already in use
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            form.email.errors.append("Email is already in use")
            return render_template('register.html', form=form)  # Return form with error messages
        
        hash_password = generate_password_hash(password=password)
        new_user = User(fullname=fullname, email=email, password=hash_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('home'))  # Redirect on success

    # Render the registration form
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        print('------>>>>>>>>>>>>>>>>>>>>>>>>>>')  # Find the user by email
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):  
            session['user_id'] = user.id 
            flash("Logged in successfully!", "success")

            return redirect(request.args.get('next', url_for('home')))  

        flash("Invalid email or password", "danger")  # Incorrect credentials

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id')
        flash('Loggout Successfully','warning')
        return redirect(url_for('home'))
    else:
        flash('your already logout')
        return redirect(url_for('home'))
    


@app.route('/recipes/new', methods=['GET', 'POST'])
@login_required  # Ensure user is logged in
def add_recipe():
    form = RecipeForm()
    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            image_filename = secure_filename(form.image.data.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            form.image.data.save(image_path)

        new_recipe = Recipe(
            recipe_name=form.recipe_name.data,
            title=form.title.data,
            description=form.description.data,
            posted_by_id=session['user_id'],
            image=image_filename,
            category=form.category.data  # Save the category from the form
        )
        db.session.add(new_recipe)
        db.session.commit()
        flash("Recipe created successfully!", "success")
        return redirect(url_for('home'))
    
    return render_template('add_recipe.html', form=form)

@app.route('/recipes/<int:recipe_id>')
def view_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)  # Get recipe or 404 if not found
    return render_template('view_recipe.html', recipe=recipe)

@app.route('/recipes/<int:recipe_id>/edit', methods=['GET', 'POST'])
@login_required  # Ensure user is logged in
def edit_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    if recipe.posted_by_id != session['user_id']:
        flash("You don't have permission to edit this recipe.", "danger")
        return redirect(url_for('view_recipe', recipe_id=recipe_id))
    
    form = RecipeForm(obj=recipe)
    
    if form.validate_on_submit():
        recipe.recipe_name = form.recipe_name.data
        recipe.title = form.title.data
        recipe.description = form.description.data
        recipe.category = form.category.data  # Update the category
        if form.image.data:
            image_filename = secure_filename(form.image.data.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            form.image.data.save(image_path)
            recipe.image = image_filename
        
        db.session.commit()
        flash("Recipe updated successfully!", "success")
        return redirect(url_for('view_recipe', recipe_id=recipe.id))
    
    return render_template('edit_recipe.html', form=form, recipe=recipe)


@app.route('/recipes/<int:recipe_id>/delete', methods=['POST'])
@login_required  # Ensure user is logged in
def delete_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    if recipe.posted_by_id != session['user_id']:
        flash("You don't have permission to delete this recipe.", "danger")
        return redirect(url_for('view_recipe', recipe_id=recipe_id))
    
    db.session.delete(recipe)
    db.session.commit()
    flash("Recipe deleted successfully!", "danger")
    return redirect(url_for('home'))






# Initialize the database and start the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)  # Start Flask with debugging enabled
