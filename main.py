#   IMPORTS
from datetime import date

from flask import Flask, flash, redirect, render_template, request, url_for, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from forms import CreatePostForm, LoginForm, RegisterUserForm, CommentForm
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps


#   FLASK APP INTIALIZE AND CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#   CK-EDITOR INITIALIZE
ckeditor = CKEditor(app)

#   BOOTSTRAP INITALIZE
Bootstrap(app)

#   LOGIN MANAGER INITAILIZE
login_manager = LoginManager(app)

#   DATABASE INTIALIZE
db = SQLAlchemy(app)

#   GRAVATAR IMAGE INITIALIZE
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


#   REGISTERED_USER  TABLE IN DATABASE
class Users(UserMixin, db.Model):
    __tablename__ = 'registered_user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    
    #   BEING IN PARENT RELATIONSHIP WITH 'BlogPost' (CHILD)
    posts = relationship('BlogPost', back_populates= 'author')
    
    #   BEING IN PARENT RELATIONSHIP WITH 'Comment' (CHILD)
    comment = relationship('Comment', back_populates='author')


#   BLOG_POSTS TABLES IN DATABASE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #   BEING IN CHILD RELATIONSHIP WITH 'Users' (PARENT)
    author = relationship('Users', back_populates='posts')
    
    #   BEING IN PARENT RELATIONSHIP WITH 'Comment' (CHILD)
    comment = relationship('Comment', back_populates='parent_post')
    
    #   Foreign Key, "registered_users.id" refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('registered_user.id'))
    
    
#   COMMENTS TABLE IN DATABASE
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.Text, nullable=False)

    #   BEING IN CHILD RELATIONSHIP WITH 'Users' I.E. (PARENT) 
    author = relationship('Users', back_populates='comment')
    #   Foreign Key, "registered_users.id" refers to the tablename of 'User'.
    author_id = db.Column(db.Integer, db.ForeignKey('registered_user.id'))

    #   BEING IN CHILD RELATIONSHIP WITH 'BlogPost' I.E. (PARENT)
    parent_post = relationship('BlogPost', back_populates='comment')
    #   Foreign Key, "blog_posts.id" refers to the tablename of 'BlogPost'.
    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    
# with app.app_context():
#     db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(Users).get(int(user_id))

def admin_only(f):
    wraps(f)
    def decorated_function(*args, **kwargs):
        
        admins = ['1']
              
        if current_user.get_id() not in admins:
            return abort(403)
        
        else:
            return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_registration_form = RegisterUserForm()
    if request.method == 'POST' and user_registration_form.validate_on_submit():

        #
        if  db.session.query(Users).filter_by(email=user_registration_form.email.data).first():
            flash('The email already exists.')
            return redirect(url_for('login'))

        new_user = Users(
            email=user_registration_form.email.data,
            name=user_registration_form.name.data,
            password=generate_password_hash(
                password=user_registration_form.password.data,
                method='pbkdf2:sha256',
                salt_length=8,
            )
        )
        db.session.add(new_user)
        db.session.commit()
        flash('You have been successfully registered. Log in.')
        return redirect(url_for('login'))
    return render_template("register.html", form=user_registration_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if request.method == 'POST' and login_form.validate_on_submit():
        user = db.session.query(Users).filter_by(
            email=login_form.email.data).first()

        #   EMAIL DOES NOT EXISTS.
        if not user:
            flash('Email does not exists. Emails are case sensitive.')

        #   INCORRECT PASSWORD.
        elif not check_password_hash(user.password, login_form.password.data):
            flash('Incorrect Passoword')

        #   SUCCESSFUL LOGIN.
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    requested_post = db.session.query(BlogPost).get(post_id)
    comment_form = CommentForm()

    if request.method == 'POST' and comment_form.validate_on_submit():
        new_comment = Comment(
            text = comment_form.comment.data,
            author_id = current_user.id,
            parent_post_id = post_id,
        )
        db.session.add(new_comment)
        db.session.commit()
    elif request.method == 'POST' and not current_user.is_authenticated:
        flash('You need to login to comment')
        return redirect(url_for('login'))

    comments_list = db.session.query(Comment).filter_by(parent_post_id = post_id).all()
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments_list)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

@login_required
@admin_only
@app.route("/new-post", methods=['GET','POST'])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@login_required
@admin_only
@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
def edit_post(post_id):
    post = db.session.get(BlogPost,post_id)
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
        post.author_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@login_required
@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
