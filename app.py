from flask import *
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound
import os
import uuid
from server.db.getdb import *
from server.ml.analyse import Analyse

UPLOAD_FOLDER = 'server/uploads/prepared/'
VONAGE_KEY = ''
VONAGE_SECRET = ''
ALLOWED_EXTENSIONS = {'csv'}
SESSION_TYPE = "redis"
PERMANENT_SESSION_LIFETIME = 1800

app = Flask(__name__)
app.config.update(SECRET_KEY=os.urandom(24))
app.config.from_object(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['VONAGE_KEY'] = VONAGE_KEY
app.config['VONAGE_SECRET'] = VONAGE_SECRET

user_sessions = {}
retour_utilisateur = {}

# Index page
@app.route('/')
def index():
    sessionid = request.cookies.get('sessionid')
    if sessionid and (sessionid in user_sessions):
        objets = getObjets()
        users = getUsers()
        return render_template('index.html', user_session=user_sessions[sessionid], objets=objets, users=users)
    else:
        return redirect('/login')
    
    
# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # retrieve form data
        username = request.form['username']
        password = request.form['password']
        password_hash = hash_password(password)
        user_id = -1
        user_index = -1

        # Check if the user exists in the database
        users = getUsers()
        for i in range(len(users)):
            if(users[i]["password_hash"] == password_hash) and (users[i]["username"] == username):
                user_id = users[i]["id"]
                user_index = i

        # If login successful
        if user_id != -1:

            user_uuid = str(uuid.uuid4())

            user_sessions[user_uuid] = users[user_index]

            resp = make_response(redirect('/'))
            resp.set_cookie("sessionid", value=str.encode(user_uuid))
            return resp

        # If login failed
        retour_utilisateur = {
            'login_failed': True,
            }
        return render_template('login.html', retour_utilisateur=retour_utilisateur)

    elif request.method == 'GET':
        retour_utilisateur = {
            'login_failed': False,
            }
        return render_template('login.html', retour_utilisateur=retour_utilisateur)


# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    
    sessionid = request.cookies.get('sessionid')
    if sessionid and (sessionid in user_sessions):
        return redirect("/")
    
    retour_utilisateur = {
            'register_failed': {
                "username":False,
                "password":False
            }
        }
    
    # If the user is not logged in, display the register page
    if request.method == 'POST':
        # retrieve form data
        numero = request.form['tel']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the username is already taken
        users = getUsers()
        for i in range(len(users)):
            if users[i]["username"] == username:
                retour_utilisateur["register_failed"]["username"] = True
                
        # Check if the password is valid
        if password != confirm_password:
            retour_utilisateur["register_failed"]["password"] = True
        
        # Check if error
        if retour_utilisateur["register_failed"]["password"] or retour_utilisateur["register_failed"]["username"]:
            return render_template('register.html', retour_utilisateur=retour_utilisateur)
        else:
            
            # Add the user to the database
            addUser(username, hash_password(password), email, numero)
            return redirect("/login")
    
    else:
        return render_template('register.html', retour_utilisateur=retour_utilisateur)


# Change user info page
@app.route('/editProfile', methods=['GET', 'POST'])
def editProfil():
    if request.method == "POST":
        sessionid = request.cookies.get('sessionid')
        if sessionid and (sessionid in user_sessions):
            username = request.form["username"]
            email = request.form["email"]
            tel = request.form["tel"]
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]

            if(password == confirm_password and hash_password(password) == user_sessions[sessionid]["password_hash"]):
                editProfile(user_sessions[sessionid]["id"], username, email, hash_password(password), tel)
                
                # Check if the user exists in the database
                user_index = 0
                users = getUsers()
                for i in range(len(users)):
                    if(users[i]["password_hash"] == hash_password(password)) and (users[i]["username"] == username):
                        user_index = i
                # Change session content
                user_sessions[sessionid] = users[user_index]

                return redirect("/")
            
            retour_utilisateur = {
                    'register_failed': {
                        "password":True
                    }
                }
            
            return render_template("editprofile.html", user_session=user_sessions[sessionid], retour_utilisateur=retour_utilisateur)
    else: 
        sessionid = request.cookies.get('sessionid')
        if sessionid and (sessionid in user_sessions):

            retour_utilisateur = {
                        'register_failed': {
                            "password":False
                        }
                    }
                
            return render_template("editprofile.html", user_session=user_sessions[sessionid], retour_utilisateur=retour_utilisateur)
        else:
            return redirect("/")




# Gestion des utilisateurs page
@app.route('/users')
def manageUsers():
    sessionid = request.cookies.get('sessionid')
    if sessionid and (sessionid in user_sessions):
        if(str(user_sessions[sessionid]["admin"]) == "1"): # admin only
            users = getUsers()
            return render_template('users.html', user_session=user_sessions[sessionid], users=users)
    return redirect('/')
    

# Edit User Request
@app.route('/users/edit', methods=['POST'])
def editUsers():
    sessionid = request.cookies.get('sessionid')
    if sessionid and (sessionid in user_sessions):
        if(str(user_sessions[sessionid]["admin"]) == "1"): # admin only

            users_old_list = getUsers()
            users_new_list = []
            objets = getObjets()

            for i in range(len(objets)): #enable to modify the database
                objets[i] = dict(objets[i])

            for id in range(0,users_old_list[len(users_old_list)-1]['id']+1):
                username = request.form.get(f'texteUsername-{id}', None)
                email = request.form.get(f'texteEmail-{id}', None)
                numero = request.form.get(f'textePhone-{id}', None)
                admin = not request.form.get(f'checkAdmin-{id}', None) is None
                for i in range(0, len(users_old_list)):
                    if users_old_list[i]['id'] == id:
                        hash = users_old_list[i]['password_hash']
                        break
                
                if not (username is None \
                    or email is None \
                    or numero is None):
                    user = {
                        'id': id, 
                        'email': email, 
                        'username': username, 
                        'password_hash': hash, 
                        'numero': numero, 
                        'admin': '1' if admin else '0'
                    }
                    users_new_list.append(user)
                else:
                    for i in range(len(objets)):
                        if objets[i]['owner'] == str(id):
                           objets[i]['owner'] = sessionid
                    

            editUser(users_new_list)
            editIoT(objets)
            
    return redirect('/users')


# Analyse page
@app.route('/analyse', methods=('GET', 'POST'))
def analyse():
    if request.method == 'POST':
        print('analyse1')
        if request.form.get('submit') == 'TRUE':
            print('analyse2')
            user_uuid = request.cookies.get('sessionid')
            if user_uuid and (user_uuid in user_sessions):
                print('analyse3')

                objet_select = "-1"
                objet_select = request.form.get('analyseSelect')

                objets = getObjets()
                canAnalyse = False
                for i in range(len(objets)):
                    if str(objets[i]["id"]) == objet_select:
                        if objets[i]['owner'] == str(user_sessions[user_uuid]["id"]) or str(user_sessions[user_uuid]["id"]) in objets[i]['acces'].split(';'):
                            canAnalyse = True

                if objet_select == '-1':
                    canAnalyse = True

                    
                if(str(user_sessions[user_uuid]['admin']) == "1"):
                    canAnalyse = True

                print('obj')
                print(objet_select)

                if(canAnalyse):

                    print('can analyse')

                    haveReseauFile = True
                    haveEnergieFile = True

                    if 'wireshark_file' not in request.files:
                        haveReseauFile = False
                    else:
                        if request.files['wireshark_file'].filename == '':
                            haveReseauFile = False

                    if 'power_file' not in request.files:
                        haveEnergieFile = False
                    else:
                        if request.files['power_file'].filename == '':
                            haveEnergieFile = False

                    print('haveReseauFile')
                    print(haveReseauFile)
                    print('haveEnergieFile')
                    print(haveEnergieFile)
                    
                    if haveReseauFile and not haveEnergieFile:
                        print('can reseau')
                        # Réseau only
                        wireshark_file = request.files['wireshark_file']
                        if wireshark_file and allowed_file(wireshark_file.filename):
                            filename_wireshark = secure_filename(wireshark_file.filename)
                            wireshark_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_wireshark))
                            
                            flash('Loading')

                            Analyse(objet_select, "", filename_wireshark)
                            return redirect(request.url)


                    if haveEnergieFile and not haveReseauFile:
                        # Energie only
                        print('can nrj')
                        
                        power_file = request.files['power_file']
                        if power_file and allowed_file(power_file.filename):
                            filename_power = secure_filename(power_file.filename)

                            power_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_power))
                            
                            flash('Loading')

                            Analyse(objet_select, filename_power, "")
                            return redirect(request.url)

                    if haveEnergieFile and haveReseauFile:
                        # les deux
                        print('can bis')

                        wireshark_file = request.files['wireshark_file']
                        power_file = request.files['power_file']
                        if wireshark_file and allowed_file(wireshark_file.filename) and power_file and allowed_file(power_file.filename):
                            filename_wireshark = secure_filename(wireshark_file.filename)
                            filename_power = secure_filename(power_file.filename)

                            wireshark_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_wireshark))
                            power_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_power))
                            
                            flash('Loading')

                            Analyse(objet_select, filename_power, filename_wireshark)
                            return redirect(request.url)

                    if not haveEnergieFile and not haveReseauFile:
                        # aucun des deux
                        print('can not')
                        flash('Merci de fournir un fichier csv de données réseau ou énergétiques')
                        return redirect(request.url)
                    else:
                        print('can not')
                        flash("Les fichiers fournis n'ont pas pu être analysés")
                        return redirect(request.url)
        # erreur -> redirect accueil
        return redirect("/")


    elif request.method == 'GET':
        sessionid = request.cookies.get('sessionid')
        if sessionid and (sessionid in user_sessions):
            objets = getObjets()
            return render_template('analyse.html', user_session=user_sessions[sessionid], objets=objets)
        return redirect("/login")
    


# Edit IoTs Request
@app.route('/iots/edit', methods=['GET', 'POST'])
def editIoTs():
    if request.method == 'GET':
        return redirect('/')
    user_uuid = request.cookies.get('sessionid')
    if user_uuid and (user_uuid in user_sessions):

        objets = getObjets()
        user = user_sessions[user_uuid]

        toCreate = []
        toDelete = []

        NomById = {}
        OwnerSelectById = {}
        AllowedUsersById = {}
        CheckEmailById = {}
        CheckTelById = {}

        for key, value in request.form.items():

            if(key.startswith("toCreate")):
                toCreate.append(key[9:])
            if(key.startswith("toDelete")):
                toDelete.append(key[9:])

                
            if(key.startswith("texteNom")):
                NomById[key[9:]]=value
                
            if(key.startswith("ownerSelect")):
                OwnerSelectById[key[12:]]=value
                
            if(key.startswith("allowedUsers")):
                splitedkey = key.split("-")
                if splitedkey[1] not in AllowedUsersById:
                    AllowedUsersById[splitedkey[1]] = []
                AllowedUsersById[splitedkey[1]].append(splitedkey[2])
            
            if(key.startswith("checkEmail")):
                CheckEmailById[key[11:]]=True
                
            if(key.startswith("checkNum")):
                CheckTelById[key[9:]]=True
                
        for j in range(len(objets)):
            objets[j] = dict(objets[j])

        #Create
        for i in range(len(toCreate)):
            hasId = False
            for j in range(len(objets)):
                if(str(objets[j]["id"]) == str(toCreate[i])):
                    hasId = True
            if not hasId:
                objets.append({
                    "id": str(toCreate[i]),
                    "nom": "",
                    "users": str(user['id']) + ":0:0",
                    "owner": str(user['id']),
                    "acces": str(user['id']),
                    "historique":"x",
                })
        #Delete
        toDelete = sorted(toDelete, reverse=True, key=int)
        
        
        for i in range(len(toDelete)):
            deleted = False
            for j in range(len(objets)):
                if not deleted:
                    if(str(objets[j]['id']) == toDelete[i] and (str(objets[j]["owner"]) == str(user['id']) or str(user['admin']) == "1")):
                        del objets[j]
                        deleted = True
        #Set props
        for i in range(len(objets)):
            if(str(user['id']) == str(objets[i]['owner']) or str(user['admin']) == "1"): # Si proprio ou admin

                if str(objets[i]['id']) in NomById:
                    if(NomById[str(objets[i]['id'])] != None):
                        objets[i]['nom'] = NomById[str(objets[i]['id'])]

                if str(objets[i]['id']) in OwnerSelectById:
                    if(OwnerSelectById[str(objets[i]['id'])] != None):
                        objets[i]['owner'] = OwnerSelectById[str(objets[i]['id'])]

                acces_string = str(objets[i]['owner']) + ";"
                if str(objets[i]['id']) in AllowedUsersById:
                    if(AllowedUsersById[str(objets[i]['id'])] != None):
                        for j in range(len(AllowedUsersById[str(objets[i]['id'])])):
                            acces_string += AllowedUsersById[str(objets[i]['id'])][j] + ";"
                objets[i]['acces'] = acces_string[:-1]


            if(str(user['id']) in objets[i]['acces'].split(';') or str(user['admin']) == "1"):
                users_string = objets[i]['users']
                users_array_from_string = users_string.split(';')

                tmpstring = str(user['id']) + ":0:0"
                if str(objets[i]['id']) in CheckEmailById:
                    if(CheckEmailById[str(objets[i]['id'])] == None):
                        tmpstring = str(user['id']) + ":0:0"
                    if(CheckEmailById[str(objets[i]['id'])] != None):
                        tmpstring = str(user['id']) + ":1:0"
                if str(objets[i]['id']) in CheckTelById:
                    if(CheckTelById[str(objets[i]['id'])] == None):
                        tmpstring = str(user['id']) + ":" + tmpstring.split(':')[1] + ":0"
                    if(CheckTelById[str(objets[i]['id'])] != None):
                        tmpstring = str(user['id']) + ":" + tmpstring.split(':')[1] + ":1"
                founded = False
                for j in range(len(users_array_from_string)):
                    if users_array_from_string[j].startswith(str(user['id'])):
                        founded = True
                        users_array_from_string[j] = tmpstring
                if not founded:
                    users_array_from_string.append(tmpstring)
                
                tmpstring2 = ""
                for j in range(len(users_array_from_string)):
                    tmpstring2 += users_array_from_string[j] + ";"

                objets[i]['users'] = tmpstring2[:-1]
                

        editIoT(objets)

    return redirect('/')


# Logout button
@app.route('/logout', methods=['GET'])
def logout():
    user_uuid = request.cookies.get('sessionid')
    if user_uuid and (user_uuid in user_sessions):
        del user_sessions[user_uuid]
    resp = make_response(redirect('/'))
    resp.set_cookie("sessionid", '', expires=0)
    return resp


# Delete account button
@app.route('/delete_account', methods=['POST'])
def delete_account():

    user_uuid = request.cookies.get('sessionid')
    if user_uuid and (user_uuid in user_sessions):
        user = user_sessions[user_uuid]
        username = user["username"]
        password = request.form['password']
        password_hash = hash_password(password)
        if(user["password_hash"] == password_hash):
            deleteUser(user["id"], username, password_hash)

        del user_sessions[user_uuid]

    resp = make_response(redirect('/'))
    resp.set_cookie("sessionid", '', expires=0)
    return resp



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# Error handler for 404 errors
@app.errorhandler(NotFound)
def page_not_found(error):
    return redirect("/")



if __name__ == "__main__":
    app.run()