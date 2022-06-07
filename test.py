import mysql.connector

db = mysql.connector.connect(
	host = "localhost",
	user = "root",
	password = "root",
	database = "webapp"
	)
cursor = db.cursor()
cursor2 = db.cursor()
sql = "select username from auth"
cursor.execute(sql)
li = cursor.fetchall()
sql2 = "select * from auth where username=''union select null,null,database() -- #'" 
cursor2.execute(sql2)
print(cursor2.fetchall())
# for i in li:
# 	sql2 = f"select * from auth where username='{str(i[0])}'"
# 	cursor2.execute(sql2)
# 	print(cursor2.fetchall())
# 	# print((str(i[0])))
# # print(cursor.fetchall())