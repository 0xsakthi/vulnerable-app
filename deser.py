import pickle
import base64



n = input("Enter a text to Decode: ")
n = base64.urlsafe_b64decode(n)
n = pickle.loads(n)
print(f" Name : {n.name}\n Departement: {n.departement} \n college: {n.college} \n Place: {n.place}")
