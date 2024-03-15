from flask import Flask,render_template,request,redirect,url_for,session
from pymongo import MongoClient
from flask_bcrypt import Bcrypt,check_password_hash
from werkzeug.security import generate_password_hash,check_password_hash
from bson.objectid import ObjectId
import re

app=Flask(__name__)
bcrypt=Bcrypt(app)
app.secret_key='maha@27'

mongoURL='mongodb://localhost:27017'
client=MongoClient(mongoURL)
db=client.prjt_mongoDb
collection_signup=db.signup
collection_trainee=db.trainee_info

def isLoggedin():
    return "username" in session

def strongPassword(password):
    if len(password)>=8:
        return True
    if re.search(r"[a-z]",password) or re.search(r"[A-Z]",password):
        return True
    if re.search(r"[!@#$%^&*()_+{}|\"<>]?",password) or re.search(r"\d",password):
        return True
    
    return True 

@app.route('/',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        login_user=collection_signup.find_one({"username":username})

        if login_user and bcrypt.check_password_hash(login_user["password"],password):
            # if isLoggedin():
            session["username"]=username
            return redirect(url_for('home'))
        else:
            return "Invalid password or username"
    return render_template('login.html')

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        
        if collection_signup.find_one({"username":username}):
            return "Username is already Exists"
        elif not strongPassword(password):
            return "Include numbers,a-z,A-Z and special characters in your password"
        else:
            hash_password=bcrypt.generate_password_hash(password).decode("UTF-8")
            userDict={"username":username,"password":hash_password}
            collection_signup.insert_one(userDict)
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/addData',methods=['GET','POST'])
def addData():
    if request.method == 'POST':
        name=request.form.get('username')
        age=request.form.get('age')
        degree=request.form.get('degree')
        year=request.form.get('year')
        course=request.form.get('course')

        traineeDict={"username":name, "age":age, "degree":degree, "year":year, "course":course}
        collection_trainee.insert_one(traineeDict)
        return redirect(url_for('home'))
    return render_template('addData.html')

@app.route('/home',methods=['GET','POST'])
def home():
    username= session["username"]
    data=collection_trainee.find({"username":username})
    return render_template('home.html',data=data)

@app.route('/editData/<string:_id>',methods=['GET','POST'])
def editData(_id):
    if request.method == 'POST':
        name=request.form.get('name')
        age=request.form.get('age')
        degree=request.form.get('degree')
        year=request.form.get('year')
        course=request.form.get('course')

        collection_trainee.update_one({"_id":ObjectId(_id)},{"$set":{"username":name, "age":age, "degree":degree, "year":year, "course":course}})
        return redirect(url_for('home'))
    data=collection_trainee.find_one({"_id":ObjectId(_id)})
    return render_template('editData.html',data=data)

@app.route('/deletedata/<string:_id>',methods=['GET','POST'])
def deleteData(_id):
    collection_trainee.delete_one({"_id":ObjectId(_id)})
    return redirect(url_for('home'))

@app.route('/')
def logout():
    session.pop('usernaem',None)
    return redirect('home')

if __name__ == '__main__':
    app.run(debug=True)