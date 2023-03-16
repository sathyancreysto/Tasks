import random,string
import bcrypt
import uuid
import secrets

staticSalt='qBgAzKkpFaVrGjg9DmYaDBVIR6WaOQAuSnIP5SHaa-ACKF4nrRwnHg'
def getDynamicSalt():
    dSalt = generateRandomString()
    return dSalt

def generateRandomString():
    randstring = secrets.token_urlsafe(43)
    return randstring

def generateUniqueKey():
    uniquekey = str(uuid.uuid4())
    return uniquekey


def generatePassword(text_password,dynamic_salt):
    #dynamicsalt = generateRandomString()
    pwd = staticSalt+text_password+dynamic_salt
    salt =bcrypt.gensalt(rounds=15)
    hashedPwd = bcrypt.hashpw(pwd.encode(),salt)    
    return hashedPwd.decode()


def checkPassword (text_password,hashed_password,dynamic_salt):
    pwd = staticSalt+text_password+dynamic_salt
    if bcrypt.checkpw(pwd.encode(), hashed_password.encode()):
        return 1
    else:
        return 0
