# -*- coding: UTF-8 -*-
#Mr. Theophilus Nutifafa
# IntelliApi
import flask
from flask import request, jsonify
import sqlite3
import os
import datetime
import time
from flask import Flask, redirect, render_template, request, url_for,session,flash
from flask_login import current_user, login_required, login_user, LoginManager, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash,generate_password_hash
import random
from flask_mail import Mail,Message
import yagmail
import flask_login
from werkzeug.utils import secure_filename
from flask import send_from_directory


# Setting up flask app, email sending capabiilities and file upload capabilities
app = Flask(__name__)
app.config["DEBUG"] = True
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']='pythonwithellie@gmail.com'
app.config['MAIL_PASSWORD']='learnpython22'
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail = Mail(app)
UPLOAD_FOLDER = '\static\img'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
WTF_CSRF_SECRET_KEY = 'somethingrandom'
app.secret_key = "something random"
login_manager = LoginManager()
login_manager.init_app(app)


# Setting up SQLalchemy database uri
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="intelliapi",
    password="codingapi",
    hostname="intelliapi.mysql.pythonanywhere-services.com",
    databasename="intelliapi$intapidp",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)
app.secret_key = "SOMETHINGYRANDOM"



#class SignupForm(FlaskForm):
    #name = TextField("Username",[validators.DataRequired()])
    #email = TextField("Email",[validators.DataRequired(),validators.Email()])
    #password = PasswordField("Password",[validators.DataRequired()])
    #submit = SubmitField('Register')





class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(128))
    email_confirmed = db.Column(db.Integer)
    token = db.Column(db.String(128))
    reset = db.Column(db.String(128))
    security = db.Column(db.String(4096))
    api_token = db.Column(db.String(4096))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_user_id(self):
        return self.id

    def get_id(self):
        return self.username

    def get_email(self,username):
        return self.email

    def get_confirmed(self,email):
        return self.confirmed
    def get_token(self,email):
        return self.token
    def get_reset(self,email):
        return self.reset
    def get_security(self,email):
        return self.security




@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()




class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(128))
    email_confirmed = db.Column(db.Integer)
    token = db.Column(db.String(128))
    reset = db.Column(db.String(128))
    security = db.Column(db.String(4096))
    api_token = db.Column(db.String(4096))
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    admin = db.relationship('User', foreign_keys=admin_id)




class Files(db.Model):

    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(4096))
    uploaded = db.Column(db.DateTime, default=datetime.datetime.now)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    uploader = db.relationship('User', foreign_keys=uploader_id)








#Homepage
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method=='GET':
        return render_template('index.html')
    user = load_user(request.form["username"])
    if request.method == "POST":
        if user is None:
            Email = request.form["email"]
            if User.query.filter_by(email=Email).first() is None:
                name = request.form["username"]
                password = generate_password_hash(request.form["password"])
                yag = yagmail.SMTP("pythonwithellie@gmail.com","learnpython22")
                Token=str(time.time()).replace(".","")
                Token=generate_password_hash(Token)
                apiTime = str(time.time()).replace(".","")
                apiToken = generate_password_hash(apiTime)


                special = "/intelliapi.pythonanywhere.com/link/"+Token
                html_msg="""<html><body style="border:solid 3px #3bc5e6;background-color:#eee;"><center><h2 style="color:#3bc5e6;">Welcome to IntelliApi
                </h2><p>Here is your verification  <a href=%(special)s>link.</a> If you cannot click on it then look below for the link and your api token.<br>
                Keep your api_token as that is what you will use to make api calls, API_TOKEN: %(apiToken)s<br>
                <br>It's so exciting having you --Welcome.!</p></center>
                </body>
                </html>""" %{"special":special,"apiToken":apiToken}



                contents=[html_msg,special,apiToken]
                yag.send(str(Email),"Verification link",contents)

                me = User(username=name,password_hash=password,email=Email,email_confirmed=0,token=Token,reset="",security="",api_token=apiToken)
                db.session.add(me)
                db.session.commit()
                #flash('A verification link has been sent to the email you provided. check now!', 'success')
                return render_template('index.html',success="check your email and click verification link to confirm")
            else:
                return render_template('index.html',error="Sorry, email exists")
        else:
            return render_template('index.html',error="Sorry, username exists")
    return render_template('index.html')






#login page control
@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("loginform.html", error=False)
    user = load_user(request.form["username"])
    if user is None:
        return render_template("loginform.html", error="Incorrect Username")
    if not user.check_password(request.form["password"]):
        return render_template("loginform.html", error="Incorrect Password")
    if user.email_confirmed == 0:
        return render_template('loginform.html',error="Please confirm your email to sign in")
    url = session.get('url',None)
    flask_login.login_user(user, remember=False)
    if not url:
        return redirect(url_for('index'))
    else:
       return redirect(url)


#Logs user out after 44640 minutes
@app.before_request
def before_request():
    min = 44640
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=min)
    flask.session.modified = True
    flask.g.user = flask_login.current_user





List=[]
List2 = []
picList = []
idList =[]
picnidList = []
@app.route("/course", methods = ['GET','POST'])
def course():

    if request.method == "GET":



        if not current_user.is_authenticated:
            session['url'] = request.url
            return render_template('new_course.html',error="Please ",image="static/images/IMG-20180227-WA0019.jpg")


        uid = current_user.id
        ufile = Files.query.filter_by(uploader_id=uid).all()
        if len(ufile)==0:
            imagename = "PyWe.jpg"
        else:
            for each in ufile:
                List.append(each.filename)
            imagename = str(List[-1])
        rawcomments=Comment.query.all()


        return render_template("new_course.html",comments=Comment.query.all(),User=current_user.username,image ="uploads/{}".format(imagename))
    if request.method == 'POST':


        uid = current_user.id
        ufile = Files.query.filter_by(uploader_id =uid).all()


        if len(ufile) ==0:
            imagename="PyWe.jpg"

        else:
            for each in ufile:
                List.append(each.filename)
            imagename = str(List[-1])

        contents=str(request.form["contents"]).encode('utf-8')
        comment = Comment(content=contents, commenter=current_user,commenter_pic=str(imagename))
        db.session.add(comment)
        db.session.commit()
        rawcomments=Comment.query.all()




        return render_template("new_course.html", comments=rawcomments,User=current_user.username,image="uploads/{}".format(imagename),cmt=contents)





@app.route("/signup", methods = ['GET','POST'])
def signup():
    if request.method=='GET':

        return render_template('trial.html',error=False, success=False)
    user = load_user(request.form["username"])
    if request.method == "POST":
        if user is None:
            Email = request.form["email"]
            if User.query.filter_by(email=Email).first() is None:
                name = request.form["username"]
                password = generate_password_hash(request.form["password"])



                yag = yagmail.SMTP("pythonwithellie@gmail.com","learnpython22")


                Token=str(time.time()).replace(".","")
                Token=generate_password_hash(Token)


                special = "/learn.pythonanywhere.com/link/"+Token
                html_msg="""<html><body style="border:solid 3px #3bc5e6;background-color:#eee;"><center><h2 style="color:#3bc5e6;">Welcome to PythonwithEllie
                </h2><br><p>Here is your verification  <a href=%s>link.</a> If you cannot click on it then look below.
                <br>It's so exciting having you --Welcome.<br>Learning Python with this team will be exciting <br>--What are you waiting for? C'mon!</p></center>
                </body>
                </html>""" %special



                contents=[html_msg,special]
                yag.send(str(Email),"Verification link",contents)
                #msg = Message('Welcome to PythonwithEllie',sender='theophylusnhutiphapha@gmail.com',recipients=([str(Email)]))
                #msg.body = "Please use this code:" +Token+ " to complete verification"
                #mail.send(msg)
                me = User(username=name,password_hash=password,email=Email,email_confirmed=0,token=Token,reset="",security="")
                db.session.add(me)
                db.session.commit()
                #flash('A verification link has been sent to the email you provided. check now!', 'success')
                return render_template('trial.html',success="check your email and click verification link to confirm")
            else:
                return render_template('trial.html',error="Sorry, email exists")
        else:
            return render_template('trial.html',error="Sorry, username exists")
    return render_template('trial.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():

    if not current_user.is_authenticated:
        session['url'] = request.url
        return redirect(url_for('login'))
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template("upload_file.html",error='No file part')
            #flash('No file part')
            #return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            return render_template("upload_file.html",error='No selected file')
            #flash('No selected file')
            #return redirect(request.url)





        if file and allowed_file(file.filename):



            firstname = str(secure_filename(file.filename))

            splitted = firstname.split('.')
            fileextension = splitted[-1].lower()
            all = ['txt', 'png', 'jpg', 'jpeg', 'gif']
            if fileextension in all:

                cur = str(time.time()).replace(".","")
                filename = str(current_user)+cur+'.'+str(fileextension) #secure_filename(file.filename)

            else:
                cur = str(time.time()).replace(".","")
                filename = str(current_user)+cur+'.'+'jpg' #secure_filename(file.filename)


            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file = Files(filename=filename, uploader=current_user)
            cmt = Comment.query.filter_by(commenter_id=current_user.id).all()
            for each in cmt:
                each.commenter_pic=filename
            db.session.add(file)
            db.session.commit()
            return render_template("upload_file.html",success='photo upload successful')
            #This is to show the file but will not be used now
            #return redirect(url_for('uploaded_file',
              #                      filename=filename))
    return render_template("upload_file.html")


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        if not current_user.is_authenticated:
            session['url'] = request.url

            return redirect(url_for('login'))
        return send_from_directory(app.config['UPLOAD_FOLDER'],
                                   filename)
    except:
        return render_template('forgotten.html',error="file doesn't exist")


@app.route("/appreciation",methods=['GET','POST'])
def appreciation():
    if request.method=='GET':
        return render_template('appreciation.html')


@app.route("/forgotten",methods=['GET','POST'])
def forgotten():
    if request.method=='GET':
        return render_template('forgotten.html',error=False,success=False)
    if request.method=='POST':
        Email = request.form["email"]
        user = User.query.filter_by(email=Email).first()
        if user is None:
            return render_template('forgotten.html',error="Your Account does not exist")
        yag = yagmail.SMTP("pythonwithellie@gmail.com","learnpython22")

        Token=str(time.time())
        Token = generate_password_hash(Token.replace(".",""))


        special = "intelliapi.pythonanywhere.com/link/"+ Token

        html_msg = """<html><body style="border:solid 3px #3bc5e6;background-color:#eee;"><h2><center style="color:#3bc5e6;">Reset your password</center></h2>
        <center><p> Please, click this <a href=%s> link </a>to reset password. If you cannot click the link then look below</a> to reset your password</p></center>
        </body>
        </html> """ %special
        contents=[html_msg,special]
        yag.send(str(Email),"Reset your password",contents)
        #setattr(user, 'reset', Token)
        #db.session.commit()
        user.reset=Token
        db.session.commit()

        return render_template('forgotten.html',success="Check your mail for link to reset password")
    return render_template('forgotten.html')



@app.route("/link/<link>",methods=['GET','POST'])
def speciallink(link):
    if request.method=='GET':
    #First check to see if the link is a token
        user=User.query.filter_by(token=link).first()
        if user is None:
            #user = User.query.filter_by(reset=link).first()
            user = User.query.filter_by(reset=link).first()
            if user is None:
                return redirect(url_for("four"))
            return redirect(url_for("reset",u_id=user.id))

        if user.email_confirmed==0:
            user.email_confirmed=1
            db.session.commit()
            Email = user.email
            return render_template("email_confirmation.html",email=Email)
        else:
            return render_template("email_confirmation.html",success="You have already confirmed your email")
    return render_template('email_confirmation.html')




@app.route("/404",methods=["GET","POST"])
def four():
    if request.method=="GET":
        return render_template("404.html")





@app.route("/reset<u_id>",methods=["GET","POST"])
def reset(u_id):
    if request.method=="get":

        user = User.query.filter_by(id=u_id).first()
        if user is None:
            return render_template("reset_pass.html",error="User does not exist")
        return render_template("reset_pass.html",error=False,success=False)


    user = User.query.filter_by(id=u_id).first()
    session['my_var'] = u_id
    return redirect(url_for('treset'))


@app.route('/rset',methods=['GET','POST'])
def treset():
    if request.method=="GET":
        my_vari = session.get('my_var', None)
        user = User.query.filter_by(id=my_vari).first()
        name = user.email

        return render_template("reset_pass.html",my_user=name)
    my_vari = session.get('my_var', None)
    user = User.query.filter_by(id=my_vari).first()


    np = request.form["password"]
    user.password_hash = generate_password_hash(np)
    user.reset=''
    db.session.commit()
    login_user(user)

    return redirect(url_for('course'))


#Google search verification page
@app.route("/google5551350abd40a242.html",methods=['Get','Post'])
def hello():
    if request.method=='GET':
        return render_template('google5551350abd40a242.html')





@app.route("/datatypes",methods=['GET','POST'])
def datatypes():


    if request.method=='GET':
        if not current_user.is_authenticated:
            session['url'] = request.url
            return render_template('data_types.html',error="please")
        uid = current_user.id
        ufile = Files.query.filter_by(uploader_id =uid).all()


        if len(ufile) ==0:
            imagename="PyWe.jpg"

        else:
            for each in ufile:
                List.append(each.filename)
                imagename = str(List[-1])


        return render_template("data_types.html",User=current_user.username,image ="uploads/{}".format(imagename))



@app.route("/image",methods=['GET','POST'])
def image():
    if request.method=='GET':
        if not current_user.is_authenticated:
            session['url'] = request.url
            return render_template('data_types.html',error="please")
        return render_template("course.html",User=current_user.username,image="Screenshot_20180217-170846.png")


imgList = []

@app.route("/slides",methods=['GET','POST'])
def slides():
    if request.method=='GET':
        if not current_user.is_authenticated:
            session['url'] = request.url
            return redirect(url_for('login'))

        ufile = Files.query.all()

        length= len(ufile)

        number=1
        return render_template('slides.html',ufile=ufile,num = number,length=length,imgnamelist=ufile)
    return redirect(url_for('login'))


imgList = []

@app.route("/user",methods=['GET','POST'])
def user():


    if request.method=='GET':

        if not current_user.is_authenticated:
            session['url'] = request.url
            return redirect(url_for('login'))
        ufile = Files.query.filter_by(uploader_id=current_user.id).all()

        length= len(ufile)

        number=1
        imagename = current_user.username


        return render_template('slides.html',ufile=ufile,num = number,length=length,imgname=imagename,error=True)
    return redirect(url_for('login'))



#Send mail to myself from user
@app.route("/mail",methods=["GET","POST"])
def mail():
    yag = yagmail.SMTP("pythonwithellie@gmail.com","learnpython22")
    name = request.form['name1']
    email = request.form["email1"]
    message1 = request.form["message"]

    html_msg = """<html><body style="border:solid 3px #3bc5e6;background-color:#eee;"><center><h3 style="color:#3bc5e6">Message from user</h3></center><center><p>Message: %(my_str1)s <br> From: %(my_str3)s<br>Reply to %(my_str2)s</p></center></body></html>""" %{"my_str1":message1,"my_str2":email,"my_str3":name}
    contents = [html_msg]

    yag.send("pythonwithellie@gmail.com","Message from user",contents)
    return redirect(url_for('index',success="Your message was sent"))



# Dict_factory to convert result to python dicctionary
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# This method shows all available data but requires authentication with api_token
@app.route('/api/v1/resources/books/all', methods=['GET'])
def api_all():
    query_parameters = request.args
    api_token = query_parameters.get('api_token')
    if not api_token:
        return page_not_found(404)

    if User.query.filter_by(api_token=api_token).first() is None:
        return page_not_found(404)
    conn = sqlite3.connect('mysite/books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_books = cur.execute('SELECT * FROM books;').fetchall()
    return jsonify(all_books)


# Another 404 handler
@app.errorhandler(404)
def page_not_found(e):
    return """<h1>404</h1><p>You need an api_token to have access to our data, visit <a href="/">Our Homepage</a> and register</p>""", 404


# Api calls handler, api_token must be provided and any other of these: id, author or date of publication
@app.route('/api/v1/resources/books', methods=['GET'])
def api_filter():
    query_parameters = request.args

    api_token = query_parameters.get('api_token')
    id = query_parameters.get('id')
    published = query_parameters.get('published')
    author = query_parameters.get('author')

    query = "SELECT * FROM books WHERE"
    to_filter = []

    if User.query.filter_by(api_token=api_token).first() is None:
        return page_not_found(404)
    if id:
        query += ' id=? AND'
        to_filter.append(id)
    if published:
        query += ' published=? AND'
        to_filter.append(published)
    if author:
        query += ' author=? AND'
        to_filter.append(author)
    if not (id or published or author):
        return page_not_found(404)
    query = query[:-4] + ';'
    conn = sqlite3.connect('mysite/books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    results = cur.execute(query, to_filter).fetchall()
    return jsonify(results)

#Logging out a user
@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__=="__main__":
    app.run()
