from flask import Flask,request,jsonify
from flask_jwt_extended import (create_access_token,create_refresh_token,get_jwt_identity,
                                JWTManager,jwt_required,get_jwt)
import dblayer as db
import encrp_algo as en
import datetime
import json

app=Flask(__name__)

######################## API HEADER KEYS #############################
registraion_key="da37d9fa3406444fefcfeffb176617b7"
user_key="c49cda8577b2b9fa8b013a1225c6d741"


######################## JWT AND CONFIGURATION #######################
jwt=JWTManager(app)

app.config["JWT_SECRET_KEY"] = "something-secret-is-written"
app.config['JWT_ACCESS_TOKEN_EXPIRES']=datetime.timedelta(minutes=10)
app.config['JWT_REFRESH_TOKEN_EXPIRES']=datetime.timedelta(minutes=15)



########################### USER REGISTRATION ######################

@app.route("/registration",methods=['POST'])
def register():
    try:
        register_api=request.headers['api_key']
    except: 
        return jsonify({"message":"api key header is missing"})
    if register_api==registraion_key:
        #registration begins here
        try:
            req=request.get_json()
            user_name=req['user_name']
            user_phone=req['user_phone']
            password=req['user_password']
            dynamic_salt=en.getDynamicSalt()
            user_email=req['user_email']
            user_password=en.generatePassword(password,dynamic_salt)
            created_on=datetime.datetime.now().strftime("%Y-%m-%d")
            query1="INSERT INTO user_information_table(user_name,user_phone,user_password,user_email,created_on,dynamic_salt) VALUES('"+str(user_name)+"','"+str(user_phone)+"','"+str(user_password)+"','"+str(user_email)+"','"+str(created_on)+"','"+str(dynamic_salt)+"');"
            result=db.dbTransactionIUD(query1)
            return result
        except:
            return jsonify({"message":"error"})    
    return jsonify({"message":"api header is wrong"})


########################## USER LOGIN ######################
@app.route("/login",methods=['POST'])
def login():
    try:
        register_api=request.headers['api_key']
    except:
        return jsonify({"message":"api key not found"})
    if register_api==registraion_key:
        req=request.get_json()
        user_name=req['user_name']
        query="SELECT user_id,user_password,dynamic_salt FROM user_information_table WHERE user_name='"+str(user_name)+"';"
        result=db.dbTransactionSelect(query)
        if result=='No data Found':
            res={'message':"user name does not exist"}
            return jsonify(res)
        else:
            password=req['user_password']
            check=en.checkPassword(password,result[0]['user_password'],result[0]['dynamic_salt'])
            if check==1:
                user_id=result[0]['user_id']
                access_token=create_access_token(identity=user_name,additional_claims={"user_id":user_id})
                refresh_token=create_refresh_token(identity=user_name,additional_claims={"user_id":user_id})
                time=datetime.datetime.now()
                log_query="INSERT INTO user_attendance_table(user_id,user_name,login_time) VALUES("+str(user_id)+",'"+str(user_name)+"','"+str(time)+"');"
                log_result=db.dbTransactionIUD(log_query)
                if log_result!="Success":
                    return log_result
                res={"access_token":access_token,"refresh_token":refresh_token}
                return jsonify(res)
            else:
                res={'message':"wrong password"}
                return jsonify(res)

        # return jsonify({"message":"login successful"})
    else:
        return jsonify({"message":"api key is wrong"})

######################## USER LOGOUT ########################
@app.route("/logout", methods=["GET"])
@jwt_required()
def logout():
    try:
        logged_api=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if logged_api==user_key:
        # process begins
        details=get_jwt()
        time=datetime.datetime.now()
        query="UPDATE user_attendance_table SET logout_time='"+str(time)+"',is_login='false' WHERE user_id="+str(details['user_id'])+" AND is_login='true';"
        log_details=db.dbTransactionIUD(query)
        if log_details!="Success":
            return log_details
        return jsonify(msg="Access token revoked")
    else:
        return jsonify({"message":"api header is wrong"})

##################### REFRESH TOKEN #########################
@app.route("/refresh",methods=['GET'])
@jwt_required(refresh=True)
def refresh():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        user_name=get_jwt_identity()
        details=get_jwt()
        access_token=create_access_token(identity=user_name,additional_claims={"user_id":details['user_id']})
        return jsonify({'access_token':access_token})
    else:
        return jsonify({"message":"api header is wrong"}) 


############################# MOTIVATOR TYPE TABLE #############################

@app.route("/addmotivator",methods=['POST'])
@jwt_required()
def add_motivator():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receive json 'type'
        query="INSERT INTO motivator_type_table(type) VALUES('"+str(req['type'])+"');"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})

    

@app.route("/showmotivator",methods=["GET"])
@jwt_required()
def show_motivator():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        query="SELECT motivator_id,type FROM motivator_type_table;"
        result=db.dbTransactionSelect(query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"message":"api header is wrong"})
    
@app.route("/deletemotivator",methods=['POST'])
@jwt_required()
def delete_motivator():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receive json 'type'
        query="DELETE FROM motivator_type_table WHERE type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})
    
######################## MOTIVATOR RESPONSE TABLE ######################

@app.route("/addmotivatorresponse",methods=['POST'])
@jwt_required()
def add_motivator_response():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives motivator_id,type as json
        motiv_id=req['motivator_id']
        res_query="INSERT INTO motivator_response_table(motivator_id,type) VALUES("+str(motiv_id)+",'"+str(req['type'])+"');"
        result=db.dbTransactionIUD(res_query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})

@app.route("/showmotivatorresponse",methods=['GET'])
@jwt_required()
def show_motivator_response():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        motiv_id=request.args.get("motivator_id") #receives motivator_id as parameter
        res_query="SELECT type FROM motivator_response_table WHERE motivator_id="+str(motiv_id)+";"
        result=db.dbTransactionSelect(res_query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"message":"api header is wrong"})

@app.route("/deletemotivatorresponse",methods=['POST'])
@jwt_required()
def delete_motivator_response():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives motivator_id,type as json
        motiv_id=req['motivator_id']
        res_query="DELETE FROM motivator_response_table WHERE motivator_id="+str(motiv_id)+" AND type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(res_query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})


############################## CALL TYPE #############################

@app.route("/addcall",methods=['POST'])
@jwt_required()
def addcall():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() # receives type as json
        query="INSERT INTO call_type_table(type) VALUES('"+str(req['type'])+"');"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})
    
@app.route("/showcall",methods=['GET'])
@jwt_required()
def showcall():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        query="SELECT call_id,type FROM call_type_table;" #return call_id,type
        result=db.dbTransactionSelect(query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"message":"api header is wrong"})
    
@app.route("/deletecall",methods=['POST'])
@jwt_required()
def deletecall():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives type as json
        query="DELETE FROM call_type_table WHERE type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})



####################### GOING TYPE TABLE ##########################


@app.route("/addcontact",methods=['POST'])
@jwt_required()
def addcontact():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives call_id,type as json
        id=req['call_id']
        query="INSERT INTO going_type_table(call_id,type) VALUES("+str(id)+",'"+str(req['type'])+"');"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})


@app.route("/showcontact",methods=['GET'])
@jwt_required()
def showcontact():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        id=request.args.get('call_id') #receives call_id as parameter
        query="SELECT call_id,going_id,type FROM going_type_table WHERE call_id="+str(id)+";" #returns going_id,type
        result=db.dbTransactionSelect(query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"message":"api header is wrong"})
    

@app.route("/deletecontact",methods=['POST'])
@jwt_required()
def deletecontact():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives call_id,type as json
        id=req['call_id']
        query="DELETE FROM going_type_table WHERE call_id="+str(id)+" AND type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})
    

############################ GOING RESPONSE TABLE ####################


@app.route("/addconversation",methods=['POST'])
@jwt_required()
def addconversation():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receive call_id,going_id,type as json
        call=req['call'] 
        id=req['call_id']
        contact_id=req['going_id']
        query="INSERT INTO going_response_table(going_id,call_id,type) VALUES("+str(contact_id)+","+str(id)+",'"+str(req['type'])+"');"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify()

@app.route("/showconversation",methods=['GET'])
@jwt_required()
def showconversation():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        id=request.args.get('call_id') #receive call_id,going_id as parameter
        contact_id=request.args.get('going_id') 
        #returns call_id,going_id,response_id,type as json
        query="SELECT call_id,going_id,response_id,type FROM going_response_table WHERE call_id="+str(id)+" AND going_id="+str(contact_id)+";"
        result=db.dbTransactionSelect(query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"message":"api header is wrong"})

@app.route("/deleteconversation",methods=['POST'])
@jwt_required()
def deleteconversation():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receives call_id,going_id,type as json
        id=req['call_id']
        contact_id=req['going_id']
        query="DELETE FROM going_response_table WHERE call_id="+str(id)+" AND going_id="+str(contact_id)+" AND type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is missing"})


######################### going promise table ########################

@app.route("/addreason",methods=['POST'])
@jwt_required()
def addreason():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() # receive call_id,going_id,response_id,type as json
        id=req['call_id'] 
        contact_id=req['going_id']
        response_id=req['response_id']
        query="INSERT INTO going_promise_table(call_id,going_id,response_id,type) VALUES("+str(id)+","+str(contact_id)+","+str(response_id)+",'"+str(req['type'])+"');"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is missing"})
    

@app.route("/showreason",methods=['GET'])
@jwt_required()
def showreason():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        id=request.args.get('call_id') #receive call_id,going_id,response_id as parameter
        contact_id=request.args.get('going_id')
        response_id=request.args.get('response_id')
        # returning promise_id,call_id,going_id,response_id,type as json
        query="SELECT promise_id,call_id,going_id,response_id,type FROM going_promise_table WHERE call_id="+str(id)+" AND going_id="+str(contact_id)+" AND response_id="+str(response_id)+";"
        result=db.dbTransactionSelect(query)
        if result=="No data Found":
            return jsonify({"message":result})
        else:
            return jsonify(result)
    else:
        return jsonify({"messge":"api header is wrong"})
    
    
@app.route("/deletereason",methods=['POST'])
@jwt_required()
def deletereason():
    try:
        header=request.headers['user_key']
    except:
        return jsonify({"message":"api header not found"})
    if header==user_key:
        req=request.get_json() #receive call_id,going_id,response_id,type as parameter
        id=req['call_id']
        contact_id=req['going_id']
        response_id=req['response_id']
        query="DELETE FROM going_promise_table WHERE call_id="+str(id)+" AND going_id="+str(contact_id)+" AND response_id="+str(response_id)+" AND type='"+str(req['type'])+"';"
        result=db.dbTransactionIUD(query)
        if result=="Success":
            return jsonify({"message":result})
        else:
            return jsonify({"message":result})
    else:
        return jsonify({"message":"api header is wrong"})

############################################################

if __name__=="__main__":
    app.run(debug=True)