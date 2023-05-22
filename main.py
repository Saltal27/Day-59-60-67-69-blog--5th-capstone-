from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, joinedload
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ManageAdmins
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Users table in db
class User(UserMixin, db.Model):
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


def add_user_db(name, email, password, status):
    with app.app_context():
        new_user = User()
        new_user.name = name
        new_user.email = email
        new_user.password = password
        new_user.status = status
        db.session.add(new_user)
        db.session.commit()


def add_comment_db(comment):
    with app.app_context():
        new_comment = PostComments()
        new_comment.name = comment
        db.session.add(new_comment)
        db.session.commit()


def owner_only(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.status != "owner":
            abort(403)
        return func(*args, **kwargs)
    return decorated_view


def admin_only(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.status != "owner" and current_user.status != "admin":
            abort(403)
        return func(*args, **kwargs)
    return decorated_view


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.options(joinedload(BlogPost.author)).all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
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
def login():
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
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
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


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
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
    PostComments.query.filter_by(post_id=post_id).delete()
    db.session.commit()

    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/manage_admins", methods=["GET", "POST"])
@owner_only
def manage_admins():
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
