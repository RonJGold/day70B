from flask import Flask,abort, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,CreateUserForm,LoginUserForm,CommentForm
from flask_gravatar import Gravatar
from wtforms.validators import DataRequired, URL
from flask_wtf import FlaskForm
from functools import wraps




app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    author = db.relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment",back_populates="parent_post")




##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship('BlogPost',back_populates="author")
    comments = db.relationship("Comment",back_populates="author")

class Comment (db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    author = db.relationship("User", back_populates="comments")
    comment = db.Column(db.Text, nullable=False)
    parent_post = db.relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer,db.ForeignKey('blog_posts.id'))








# Line below only required once, when creating DB.
# Drop existing tables

# Recreate tables with updated models
with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(fnc):
    @wraps(fnc)
    def inner_function(*args, **kwargs):
        if current_user.id !=1:
            return abort(403)
        else:
            return fnc(*args, **kwargs)
    return inner_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)


@app.route('/register',methods=['GET', 'POST'])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        form_data = form.data
        user = User.query.filter_by(email=form_data['email']).first()
        if user:
            flash("You've already signed up with that email, log in instead!")


            return redirect(url_for('login'))
        else:

            password = form_data["password"]
            hash_password = generate_password_hash(password=password, salt_length=8, method='pbkdf2:sha256')
            with app.app_context():
                new_user = User(email=form_data["email"],
                                name=form_data["name"],
                                password=hash_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for("get_all_posts"))


    return render_template("register.html",form=form)


@app.route('/login',methods=["POST","GET"])
def login():
    error = None
    form = LoginUserForm()


    if form.validate_on_submit():

        data = form.data
        user = User.query.filter_by(email=data['email']).first()
        if user:
            password = data['password']
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts',user_id=user.id))
            else:
                flash("Incorrect Password!")

                return redirect(url_for('login'))



        else:
            flash("You've already signed up with that email, log in instead!")

            return redirect(url_for('login'))

    return render_template("login.html", logged_in=current_user.is_authenticated,form=form,error=request.args.get('error'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["POST","GET"])
def show_post(post_id):
    comments = Comment.query.all()





    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            data = form.data
            with app.app_context():
                new_commet = Comment(post_id=post_id,comment=data['comment'],author_id=current_user.id)
                db.session.add(new_commet)
                db.session.commit()


        else:
                flash("Only logged in accounts can comment")
                return redirect(url_for('login'))



    return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated,form=form,comments=comments)


@app.route("/about")
def about():
    return render_template("about.html",logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html",logged_in=current_user.is_authenticated)


@app.route("/new-post",methods=["POST","GET"])
@admin_only

def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,logged_in=current_user.is_authenticated)

@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only

def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
