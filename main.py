from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import CreatePostForm, RegisterForm,LoginForm,CommentForm
from functools import wraps



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_owner(post_id):
    owner = BlogPost.query.get(post_id).author
    if current_user.id !=1  and current_user !=owner :
        return False
    return True



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String)
    user = relationship("User", back_populates="comments")
    post = relationship("BlogPost",back_populates='comments')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String(250), nullable=False, unique = True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    #add data to the author property in the BlogPost class
    posts = relationship('BlogPost',back_populates='author') 
    comments = relationship("Comment",back_populates='user')
##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    #ketika di input author = current user, lgsg ketauan author id nya
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts") #kenapa back populates harus posts mungkin pas blog post dibuat dikasitau current_usernya
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment',back_populates='post')
with app.app_context():
    db.create_all()

@app.route('/')
def get_all_posts():
    admin = False
    is_login=False
    if current_user.is_authenticated:
        is_login = True
        if current_user.id == 1:
            admin = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts ,is_admin = admin,is_login=is_login, current_user=current_user)


@app.route('/register', methods = ['POST','GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        inputted_email = form.email.data.lower()
        if User.query.filter_by(email=inputted_email).first():
            flash("Email already registered! Please log in instead")
            return redirect(url_for('login'))
        new_user = User(
            email = form.email.data.lower(),
            password = generate_password_hash(form.password.data, method ='pbkdf2:sha256', salt_length=8),
            name = form.name.data,
        )
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",form =form)


@app.route('/login',methods = ['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        inputted_email = form.email.data.lower()
        inputted_password = form.password.data
        print(inputted_password)
        user = User.query.filter_by(email=inputted_email).first()
        with app.app_context():
            if user is not None:
                if check_password_hash(user.password, inputted_password):
                    login_user(user)
                    return redirect(url_for('get_all_posts'))
                else:
                    flash('Wrong Password!')
                    return redirect(url_for('login'))
            else:
                flash("Email doesn't exist!")
                return redirect(url_for('login'))


    return render_template("login.html",form = form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['POST','GET'])
@login_required
def show_post(post_id):
    is_admin = check_owner(post_id)
    with app.app_context():
        comments = Comment.query.filter_by(post_id =post_id)
        form = CommentForm()
        requested_post = BlogPost.query.get(post_id)
        if form.validate_on_submit():
            new_comment = Comment(text = form.comment.data,
            user = current_user,
            post = requested_post)
            db.session.add(new_comment)
            db.session.commit()
    
        return render_template("post.html", post=requested_post, form=form, comments = comments,is_admin = is_admin)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods =['POST','GET'])
@login_required
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>",methods =['POST','GET'])
@login_required
def edit_post(post_id):
    is_admin = check_owner(post_id)
    if not is_admin:
        return abort(403)
    admin = False
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_admin = admin)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    is_admin = check_owner(post_id)
    if not is_admin:
        return abort(403)
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
