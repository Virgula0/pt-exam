import requests as r
import string

url = "http://172.17.0.2/login.php"
bad = "Username or password are in the wrong format."

for x in string.printable:
    response = r.post(url=url, data={"username":x, "password":"we"})
    
    if bad in response.text:
        print(f"Character {x} ({ord(x)})not admitted")
