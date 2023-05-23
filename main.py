from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, joinedload
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ManageAdmins, ContactMe
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import smtplib
import os

MY_EMAIL = os.environ.get("MY_EMAIL")
MY_PASSWORD = os.environ.get("MY_PASSWORD")

# ------------------ Initializing A Flask App With Some Extensions --------------------- #
# Initialize the Flask app and set a secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# Initialize the CKEditor extension
ckeditor = CKEditor(app)

# Initialize the Bootstrap extension
Bootstrap(app)

# Initialize the Gravatar extension wit default parameters
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Initialize the Flask-Login extension
login_manager = LoginManager()
login_manager.init_app(app)

# Set up the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ---------------------------- DB Tables ------------------------------- #
# Users table in db
class User(UserMixin, db.Model):
    """
    A class representing the users table in the database.

    Attributes:
    id (int): The unique identifier of the user.
    email (str): The email address of the user.
    password (str): The password of the user.
    name (str): The name of the user.
    status (str): The status of the user.
    posts (Relationship): The posts made by the user.
    comments (Relationship): The comments made by the user.

    Methods:
    __repr__(): Returns a string representation of the user.
    """

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    status = db.Column(db.String)
    posts = db.relationship('BlogPost', backref='author', lazy=True)
    comments = db.relationship('PostComments', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.name}>'


# Blog posts table in db
class BlogPost(db.Model):
    """
    A class representing the blog_posts table in the database.

    Attributes:
    id (int): The unique identifier of the blog post.
    title (str): The title of the blog post.
    subtitle (str): The subtitle of the blog post.
    date (str): The date the blog post was posted.
    body (str): The content of the blog post.
    img_url (str): The URL of the image for the blog post.
    user_id (int): The unique identifier of the user who created the blog post.
    comments (Relationship): The comments made on the blog post.

    Methods:
    __repr__(): Returns a string representation of the blog post.
    """

    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = db.relationship('PostComments', backref='blog_post', lazy=True)

    def __repr__(self):
        return f'<BlogPost {self.title}>'


# Comments table in db
class PostComments(db.Model):
    """
    A class representing the comments table in the database.

    Attributes:
    id (int): The unique identifier of the comment.
    text (str): The text of the comment.
    date (str): The date the comment was posted.
    user_id (int): The unique identifier of the user who made the comment.
    post_id (int): The unique identifier of the blog post the comment was made on.

    Methods:
    __repr__(): Returns a string representation of the comment.
    """
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f'<Comment {self.id}>'


# with app.app_context():
#     db.create_all()


# ---------------------------- Custom Functions ------------------------------- #
# Create a custom function to add users to the database
def add_user_db(name, email, password, status):
    """
    A custom function to add a new user to the database.

    Parameters:
    name (str): The name of the new user.
    email (str): The email address of the new user.
    password (str): The password of the new user.
    status (str): The status of the new user.

    Returns:
    None
    """

    with app.app_context():
        new_user = User()
        new_user.name = name
        new_user.email = email
        new_user.password = password
        new_user.status = status
        db.session.add(new_user)
        db.session.commit()


# Create a custom decorator to restrict access to owner-only pages
def owner_only(func):
    """
    A custom decorator to restrict access to owner-only pages.

    Parameters:
    func (function): The function being decorated.

    Returns:
    function: The decorated function.
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.status != "owner":
            abort(403)
        return func(*args, **kwargs)

    return decorated_view


# Create a custom decorator to restrict access to admin-only pages
def admin_only(func):
    """
    A custom decorator to restrict access to admin-only pages.

    Parameters:
    func (function): The function being decorated.

    Returns:
    function: The decorated function.
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.status != "owner" and current_user.status != "admin":
            abort(403)
        return func(*args, **kwargs)

    return decorated_view


# Create a custom decorator to restrict access to non-logged-in users
def logout_required(func):
    """
    A decorator function that restricts access to a route to only logged-out users.

    Args:
    func: The function to be decorated.

    Returns:
    function: The decorated function.
    """

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash('You must log out to access this page.')
            return redirect(url_for('get_all_posts'))
        return func(*args, **kwargs)

    return decorated_function


# Set up the user loader function
@login_manager.user_loader
def load_user(user_id):
    """
    A function to load a user from the database.

    Parameters:
    user_id (int): The ID of the user to be loaded.

    Returns:
    object: The user with the specified ID.
    """

    return User.query.get(int(user_id))


# ---------------------------- Main Pages Routes ------------------------------- #
@app.route('/')
def get_all_posts():
    """
    A route to display all the blog posts.

    Returns:
    str: The rendered HTML template with all the blog posts.
    """

    posts = BlogPost.query.options(joinedload(BlogPost.author)).all()
    return render_template("index.html", all_posts=posts)


@app.route("/about")
def about():
    """
    A route to display the about page.

    Returns:
    str: The rendered HTML template for the about page.
    """

    return render_template("about.html")


@app.route("/contact", methods=["POST", "GET"])
def contact():
    """
    A route to display the contact page.

    Returns:
    str: The rendered HTML template for the contact page.
    """

    contact_form = ContactMe()
    if contact_form.validate_on_submit():
        name = contact_form.name.data
        email = contact_form.email.data
        phone = contact_form.phone_number.data
        message = contact_form.message.data
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=60) as connection:
                connection.starttls()
                connection.login(user=MY_EMAIL, password=MY_PASSWORD)
                connection.sendmail(
                    from_addr=MY_EMAIL,
                    to_addrs="omarmobarak53@gmail.com",
                    msg=f"Subject: New message from a 'Omar's Blog' user\n\n"
                        f"Name: {name}\n"
                        f"Email: {email}\n"
                        f"Phone Number: {phone}\n"
                        f"Message: {message}\n"
                )
        except smtplib.SMTPException:
            flash("Sorry, there was an error sending your message, please try again later.")
        else:
            span = "Successfully sent your message!"

    else:
        span = "Have questions? I have answers."
    return render_template("contact.html", contact_form=contact_form, span=span)


# ---------------------------- Posts Managing Routes ------------------------------- #
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    """
    A route to display a single blog post and its comments.

    Parameters:
    post_id (int): The ID of the blog post to be displayed.

    Returns:
    str: The rendered HTML template for the blog post and its comments.
    """

    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            with app.app_context():
                new_comment = PostComments(
                    text=comment_form.comment.data,
                    date=date.today().strftime("%B %d, %Y"),
                    user_id=current_user.id,
                    post_id=post_id
                )
                db.session.add(new_comment)
                db.session.commit()
        else:
            flash("You need to register / login in order to comment.")
            return redirect(url_for("login"))

    requested_post = BlogPost.query.get(post_id)
    all_post_comments = requested_post.comments
    return render_template(
        "post.html",
        post=requested_post,
        comment_form=comment_form,
        all_post_comments=all_post_comments
    )


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    """
    A route to add a new blog post.

    Returns:
    str: The rendered HTML template for creating a new blog post.
    """

    form = CreatePostForm()
    h1 = "New Post"
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                date=date.today().strftime("%B %d, %Y"),
                user_id=current_user.id
            )
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form, h1=h1)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    """
    A route to edit an existing blog post.

    Parameters:
    post_id (int): The ID of the blog post to be edited.

    Returns:
    str: The rendered HTML template for editing a blog post.
    """

    post = BlogPost.query.get(post_id)
    h1 = "Edit Post"
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, h1=h1)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    """
    A route to delete an existing blog post.

    Parameters:
    post_id (int): The ID of the blog post to be deleted.

    Returns:
    str: A redirection to the main blog page after deleting the post.
    """

    PostComments.query.filter_by(post_id=post_id).delete()
    db.session.commit()

    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# ---------------------------- Users Managing Routes ------------------------------- #
@app.route('/register', methods=["POST", "GET"])
@logout_required
def register():
    """
    A route to register a new user.

    Returns:
    str: The rendered HTML template for registering a new user.
    """

    register_form = RegisterForm()
    if register_form.validate_on_submit():
        name = register_form.name.data
        email = register_form.email.data
        password = register_form.password.data
        confirm_password = register_form.confirm_password.data
        salted_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        existing_user = User.query.filter_by(email=email).first()

        if existing_user is None:
            if password == confirm_password:
                add_user_db(name, email, salted_hash, "member")
                user = User.query.filter_by(email=email).first()
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Passwords don't match, please try again.")

        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

    return render_template("register.html", register_form=register_form)


@app.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    """
    A route to log in an existing user.

    Returns:
    str: The rendered HTML template for logging in an existing user.
    """

    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Incorrect password, please try again.')
        else:
            flash('Email does not exist, please try again.')

    return render_template('login.html', login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    """
    A route to log out the current user.

    Returns:
    str: A redirection to the main blog page after logging out.
    """

    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/manage_admins", methods=["GET", "POST"])
@owner_only
def manage_admins():
    """
    A route to manage the admin status of users.

    Returns:
    str: The rendered HTML template for managing the admin status of users.
    """

    manage_admins_form = ManageAdmins()
    subheading = "Time to promote / demote some users!"

    if manage_admins_form.validate_on_submit():
        email = manage_admins_form.email.data
        user = User.query.filter_by(email=email).first()

        if user:  # Check if the email matches an existent user
            if manage_admins_form.promote.data:  # Check if the promote button had been clicked
                if user.status == "member":  # Check the user's original status
                    user.status = "admin"
                    db.session.commit()
                    subheading = f"Successfully promoted {user.name} to an admin!"
                else:
                    flash("This user is already an admin.")

            elif manage_admins_form.demote.data:  # Check if the demote button had been clicked
                if user.status == "admin":  # Check the user's original status
                    user.status = "member"
                    db.session.commit()
                    subheading = f"Successfully demoted {user.name} to a member!"
                else:
                    flash("This user is already a member.")

        else:
            flash('Email does not exist, please try again.')

    return render_template(
        'manage-admins.html',
        manage_admins_form=manage_admins_form,
        subheading=subheading
    )


if __name__ == "__main__":
    app.run(debug=True)
