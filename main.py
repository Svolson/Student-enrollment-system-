from flask import Flask, render_template , url_for , redirect , request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user , LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField , EmailField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SECRET_KEY"] = "thisisasecretkey"



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Creating model table for our CRUD database
class User(db.Model , UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)

    
    def __init__(self, username, password, email):

        self.username = username
        self.password = password
        self.email = email



#registerform
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Username'})

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    submit = SubmitField('Register')


    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()

        if existing_user_email:
            raise ValidationError(
                "That email already exists.")



#LoginForm
class LoginForm(FlaskForm):

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    submit = SubmitField('Login')



#adminform
class AdminForm(FlaskForm):

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    Email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    submit = SubmitField('Admin login')





@app.route('/')
def home():
    return render_template("home.html")




@app.route('/dashboard' , methods=["GET", "POST"])
def dashboard():
    
    return render_template("marks.html")



@app.route('/logout' , methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
    




@app.route('/login' , methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
       
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))

    return render_template("login.html" , form=form)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html" , form=form)



@app.route('/admin' , methods=["GET", "POST"])
def admin():
    form = AdminForm()
    

    return render_template("admin.html" , form=form)

#This is the index route where we are going to
#query on all our employee data
@app.route('/index')
def Index():
    all_data = User.query.all()

    return render_template("index.html", User = all_data)



#this route is for inserting data to mysql database via html forms
@app.route('/insert', methods = ['POST'])
def insert():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
    


        my_data = User(username, password)
        db.session.add(my_data)
        db.session.commit()

        flash("Employee Inserted Successfully")

        return redirect(url_for('Index'))


#this is our update route where we are going to update our employee
@app.route('/update', methods = ['GET', 'POST'])
def update():

    if request.method == 'POST':
        my_data = User.query.get(request.form.get('id'))

        my_data.name = request.form['name']
        my_data.password = request.form['password']

        db.session.commit()
        flash("Employee Updated Successfully")

        return redirect(url_for('Index'))




#This route is for deleting our employee
@app.route('/delete/<id>/', methods = ['GET', 'POST'])
def delete(id):
    my_data = User.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Employee Deleted Successfully")

    return redirect(url_for('Index'))



if __name__ == "__main__":
    app.run(debug=True)
