import mysql.connector
# from flask import Flask,render_templates,render_template_string
from flask import Flask,request,render_template_string,render_template,redirect,url_for, session,make_response
import os
import pickle
from base64 import b64decode,b64encode
import base64
import smtplib
app = Flask(__name__)
db = mysql.connector.connect(
	host = "localhost",
	user = "root",
	password = "root",
	database = "webapp"
)

#smtp creds
server  = smtplib.SMTP("smtp.gmail.com",587)
server.starttls()
email = "hacko2852@gmail.com"
server.login("subiramaniyan2805@gmail.com","Subiramaniyan@2002")
app.secret_key = 'not_easy'

#LLFI inclusion and SSTI
@app.route("/lfissti")
def hello_ssti():
	person = {'name':"world", 'secret':"Admin,Hello my login page have some security flaw :( so i recently changed my admin panel path into /XXX (i saved my login path at my secret.txt)\n Hint Z2V0X3VzZXJfZmlsZSBmdW5jdGlvbiBpbiB1bmRlciBkZXZlbG9waW5nCg== "}
	if request.args.get('name'):
		person['name'] = request.args.get('name')
	template = '''<h3>You Can Also Print Your Name by using ?name= :)
	</h3><br><h2>Hello %s!</h2><br>
	<script>can you find the **secret** ?<script>
	''' % person['name']+'''
	<script>
	<!-- @app.route("/lfissti")
def hello_ssti():
	person = {'name':"world", 'secret':"XXXXX [REDACTED] "}
	if request.args.get('name'):
		person['name'] = request.args.get('name')
	template = <h3>You Can Also Print Your Name by using ?name= :
	</h3><br><h2>Hello %s!</h2><br>
	<script>can you find the **secret** ?<script>
	<script> % person['name']
	return render_template_string(template, person=person) -->
	</script>
	'''
	return render_template_string(template, person=person)
def get_user_file(f_name):
	with open(f_name) as f:
		return f.readlines()
#give permission to access the get_user_file in jinja template 
app.jinja_env.globals['get_user_file'] = get_user_file

@app.route("/sqliadmin",methods=["POST","GET"])
def hello_sql():
	#prepared statment
	cursor = db.cursor(prepared=True)
	if(request.method=="POST"):
		username = request.form.get("username")
		password = request.form.get("password")
		level = "USER"
		sql = "insert into auth(username,password,Level) values(%s,%s,%s)"
		insertdata = (username,password,level)
		cursor.execute(sql,insertdata)
		print(sql)
		db.commit()
		return render_template("register.html",string="Account was Created")
	if(request.method=="GET"):
		return render_template("register.html")

@app.route("/check",methods=["POST","GET"])
def view():
	cursor = db.cursor()
	cursor2 = db.cursor()
	data = ""
	if(request.method=="GET"):
		sql = f"select * from auth"
		cursor.execute(sql)
		li = list(cursor.fetchall())
		for i in li:
			try:
				sql2 = f"select username,level from auth where username='{str(i[0])}'"
				cursor2.execute(sql2)
				# cursor2.fetchall()
				data+=str(cursor2.fetchall())+"\n"
			except mysql.connector.Error as err:
				data+="\n"+str(err)+"\n"
	# print(data)
	return render_template_string(data)
def check(loginusername,loginpassword):
	cursor3 = db.cursor(prepared=True)
	sql = '''select username from auth where username=%s and password=%s'''
	insertdata = (loginusername,loginpassword)
	cursor3.execute(sql,insertdata)
	li = list(cursor3.fetchall())
	print(li)
	if len(li)==1 and li[0][0]==loginusername:
		return True
	else:
		return False
@app.route("/login",methods=["POST","GET"])
def login():
	loginusername = request.form.get("username")
	loginpassword = request.form.get("password")
	if request.method=="POST":
		if (check(loginusername,loginpassword)):
			session["user"] = loginusername
			session.permanent = True
			return redirect("dashboard")
	# if request.method=="GET":
	return render_template("login.html",string={"Authentication Failed"})
@app.route("/")
def home():
	if "user" in session:
		return redirect(url_for("dash"))
	return render_template("login.html")
@app.route("/dashboard")
def dash():
	try:
		name = session['user']
		cook = request.cookies.get("session")
		if cook == "eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyIjoiWm9ob0FkbWluIn0.Yo18yg.n_3qZm36A84A4vlgcmAJjkKnN-A":
			return redirect(url_for("cookie"))
		if name=="ZohoManager":
			return render_template("index.html")
		return f"Hi {name}"
	except:
		return "error in session(no that user session available)"

#Derserilization
@app.route('/cookie', methods = ['POST', 'GET'])
def cookie():
    cookieValue = None
    value = None
    if request.method == 'POST':
    	cookieValue = request.form['value']
    	value = cookieValue
    elif "value" in request.cookies:
    	cookieValue = pickle.loads(b64decode(request.cookies['value']))
    # data = base64.urlsafe_b64decode(request.cookies['value'])
    try:
    	data = base64.urlsafe_b64decode(value)
    	deserialized = pickle.loads(data)
    	print(deserialized)
    except:
    	data = base64.urlsafe_b64decode(request.cookies['value'])
    	deserialized = pickle.loads(data)
    resp = make_response(render_template("index.html",cookievalue=cookieValue,oldcookievalue=deserialized))
    if value:
    	resp.set_cookie('value', b64encode(pickle.dumps(value)))
    return resp

#		HOST HEADER INJECTION 

def passresetmaillsender(email,host):
   message = """From: From Person <Auth@headerinjection.Com>
      To: To Person {}
      Subject: SMTP e-mail test

      This is your Password Reset Link {}/asdadojsoajnsj.
      """.format(email,host)
   # print(message+"\n",l)
   print(type(message))
   server.sendmail("subiramaniyan2805@gmail.com",email,message)

@app.route("/passreset",methods=["POST","GET"])
def reset_maill():
   if(request.method=="POST"):
      host = request.headers.get("host")
      name = request.form.get("username")
      pas = request.form.get("password")
      passresetmaillsender(name,host)
      return "successfully sended"
   else:
   	return render_template("passreset.html")

#		USE ALLOWED TO PREVENT THEM

#CORS CROSS ORGIN REQUEST SHARING
@app.route("/cors")
def cors():
	json = {"name":"Zoho Database",
	"description":"Internal Database"
	"DB":"/sensitiveData/sql.db",
	"Access":"Db.Zoho.Com"
	"Type":"Beta"
	}
	return json

