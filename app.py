import mysql.connector
# from flask import Flask,render_templates,render_template_string
from flask import Flask,request,render_template_string,render_template,redirect,url_for, session,make_response,abort
import os
import pickle
from base64 import b64decode,b64encode
import base64
import smtplib
from lxml import etree
import requests
class serilize:
	name = ""
	departement = ""
	college=""
	place=""
proxies = {"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}
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
server.login("subiramaniyan2805@gmail.com","dbibthcbbjjmuttv")
app.secret_key = 'not_easy'


@app.route("/<e>")
def not_found(e):
	# pagename = request.args.get("url")
	# print(pagename)
	html = "<html><h1>Requested url \"%s\" is not Found</h1></html> "%e
	return render_template_string(html)


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
	print(f"check is called{li}")
	if len(li)!=0 and li[0][0]==loginusername:
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

@app.route("/lfi",methods=["POST","GET"])
def home2():
	html = "Enter File Name to Read: <form action='/lfi' method='POST'><input type=text name=name><br><br><input type=submit></form>"
	if request.method=="POST":
		try:
			file = request.form.get("name")
			f = open(file, "r")
			return f.read()
		except:
			return render_template_string("<h1>FILE Not found<h1>")
	return render_template_string(html)

@app.route('/xml', methods = ['POST', 'GET'])
def xml():
	if request.method == 'POST':
		parsed_xml = None
		xml = request.form['xml']
		parser = etree.XMLParser(no_network=False, dtd_validation=False, load_dtd=True, huge_tree=True)
		doc = etree.fromstring(xml.encode(), parser)
		parsed_xml = etree.tostring(doc).decode('utf8')
		return html.escape(parsed_xml)
	return """
       <html>
             <form action = "/xml" method = "POST">
                <p><h3>Enter xml to parse</h3></p>
                <textarea class="input" name="xml" cols="40" rows="5"></textarea>
                <p><input type = 'submit' value = 'Parse'/></p>
             </form>
          </body>
       </html>
       """
#CORS CROSS ORGIN REQUEST SHARING
@app.route("/cors")
def cors():
	json = {"name":"Zoho Database",
	"description":"Internal Database",
	"DB":"/sensitiveData/sql.db",
	"Access":"Db.Zoho.Com",
	"Type":"Beta"
	}
	return json

@app.route("/sensitiveData/sql.db")
def origincheck():
	print(request.headers.get(""))
	if request.headers.get("origin")=="Db.Zoho.com":
		return abort(200,"Zoho_CTF{this is Flag}")
	else:
		return abort(401,"you are unauthorized")
@app.route('/upload')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST','GET'])
def upload_file():
	if request.method=="POST":
		uploaded_file = request.files['file']
		if uploaded_file.filename != '':
			uploaded_file.save(uploaded_file.filename)
		return redirect('upload.html')
	else:
		return render_template("upload.html")

# XSS

def add_comment(username,data):
	cursor = db.cursor(prepared=True)
	sql = '''insert into comments (username,message) values(%s,%s)'''
	insertdata = (username,data)
	# (comment)
	cursor.execute(sql,tuple(insertdata))
	db.commit()

def get_comments(search_query=None):
	res = []
	cursor = db.cursor()
	get_all_query = 'select message from comments'
	cursor.execute(get_all_query)
	temp = cursor.fetchall()
	for i in temp:
		print(i)
		if i!=" " and search_query!=None:
			if search_query in i[0]:
				res.append(i[0])
			if i!=" " and search_query==None:
				res.append(i[0])
	return res

@app.route('/xss', methods=['GET', 'POST'])
def xss():
	if request.method == 'POST':
		add_comment(request.form['username'],request.form['comment'])
	search_query = request.args.get('q')
	# print(search_query)
	comments = get_comments(search_query)
	print(comments)
	return render_template('xss.html',comments=comments,search_query=search_query)

#serilization
@app.route("/object",methods=["GET","POST"])
def object():
	if request.method == "GET":
		return render_template("reg.html")
	obj = serilize()
	obj.name=request.form.get("uname")
	obj.departement = request.form.get("udept")
	obj.college = request.form.get("uclg")
	obj.place  = request.form.get("uplace")
	serilizeable_data = pickle.dumps(obj)
	b64 = base64.urlsafe_b64encode(serilizeable_data)
	print(b64)
	jk = {"name":obj.name,"data":str(b64)}
	requests.post("http://127.0.0.1:5000/save",json=jk,proxies=proxies,verify=False)
	return redirect(url_for("savedata"))

@app.route("/save",methods=["POST","GET"])
def savedata():
	cursor3 = db.cursor(prepared=True)
	sql = '''insert into serilize values(%s,%s)'''
	dat = request.get_json()
	name = dat['name']
	dat = dat['data']
	dat = dat.split("\'")
	insertdata = (name,str(dat[1]))
	cursor3.execute(sql,insertdata)
	db.commit()
	n = pickle.loads(base64.urlsafe_b64decode(dat[1]))
	res = (f" Name : {n.name}\n Departement: {n.departement} \n college: {n.college} \n Place: {n.place}")
	# res = f"your name was : {datk.name} \n your age was {datk.age}"
	response = make_response(res)
	response.headers["Content-Type"] = "application/json"
	return response