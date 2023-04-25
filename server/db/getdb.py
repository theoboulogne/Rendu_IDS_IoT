import sqlite3
from hashlib import sha256

def get_db_connection():
    conn = sqlite3.connect('server/db/bdd.db')
    conn.row_factory = sqlite3.Row
    return conn

def getUsers():
    conn = get_db_connection()
    contacts = conn.cursor().execute('SELECT * FROM users').fetchall()
    conn.close()
    return contacts

def getObjets():
    conn = get_db_connection()
    objets = conn.cursor().execute('SELECT * FROM objets').fetchall()
    conn.close()
    return objets

def hash_password(password: str) -> str:
    """Hash a password using SHA256.

    Args:
        password: A string representing the password.

    Returns:
        A string representing the hashed password.
    """
    return sha256(password.encode()).hexdigest()


def editIoT(iots):

    conn = get_db_connection()
    cur = conn.cursor()

    # Supprimer les données existantes dans la table "objets"
    cur.execute('DELETE FROM objets')

    for objet in iots:
        print(objet)
        cur.execute('INSERT INTO objets (id, nom, users, owner, acces, historique) VALUES (?, ?, ?, ?, ?, ?)',
                    (objet['id'], objet['nom'], objet['users'], objet['owner'], objet['acces'], objet['historique']))

    # Valider les modifications et fermer la connexion à la base de données
    conn.commit()
    conn.close()


def addUser(username, password_hash, email, numero):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("INSERT INTO users (email, username, password_hash, numero, admin) VALUES (?, ?, ?, ?, ?)", 
    (email, username, password_hash, numero, "0"))

    # Valider les modifications et fermer la connexion à la base de données
    conn.commit()
    conn.close()

def deleteUser(id, username, password_hash):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE id=? AND username=? AND password_hash=?", (id, username, password_hash))

    # Valider les modifications et fermer la connexion à la base de données
    conn.commit()
    conn.close()
    
def editUser(users):
    conn = get_db_connection()
    cur = conn.cursor()

    # Supprimer les données existantes dans la table "users"
    cur.execute('DELETE FROM users')

    for user in users:
        cur.execute('INSERT INTO users (id, email, username, password_hash, numero, admin) VALUES (?, ?, ?, ?, ?, ?)',
                    (user['id'], user['email'], user['username'], user['password_hash'], user['numero'], user['admin']))
        
    # Valider les modifications et fermer la connexion à la base de données
    conn.commit()
    conn.close()


def editProfile(id, username, email, password_hash, numero):
    conn = get_db_connection()
    cur = conn.cursor()

    # On met a jour le profil
    cur.execute('UPDATE users SET email=?, username=?, password_hash=?, numero=? WHERE id=?',
            (email, username, password_hash, numero, id))
        
    # Valider les modifications et fermer la connexion à la base de données
    conn.commit()
    conn.close()


    
def addHistorique(id_objet, contenu):
    conn = get_db_connection()
    cur = conn.cursor()

    # Récupération du contenu de l'historique actuel de l'objet
    cur.execute("SELECT historique FROM objets WHERE id=?", (id_objet,))
    historique = cur.fetchone()[0]

    # Concaténation du nouveau texte avec l'historique existant
    nouvel_historique = historique + ";" + contenu
    if historique == "x":
        nouvel_historique = contenu

    # Mise à jour de la base de données avec le nouvel historique
    cur.execute("UPDATE objets SET historique=? WHERE id=?", (nouvel_historique, id_objet))

    conn.commit()
    conn.close()
