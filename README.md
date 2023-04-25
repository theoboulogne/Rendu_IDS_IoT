# IDS_IoT

![Presentation](https://theoboulogne.com/temp/CaptureIoT.PNG)

-----------------
## Commandes d'installation

Pour installer ce projet il est nécessaire d'installer Python et pip. Ensuite il faut installer les dépendances avec les commandes suivantes :

```bash
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
pip install flask
pip install vonage
pip install tabulate
pip install -U scikit-learn
pip install keras
pip install numpy
pip install pandas
```

-----------------
## Récupération de la BDD

Si la base de données est corrompue il est possible de la récupérer au lien suivant : [Drive](https://drive.google.com/file/d/1fl2ZIrbbf-EadTryHTVRkBtF9NLalJa0/view?usp=share_link)  
Il faut ensuite la placer dans le dossier "/server/db" en remplaçant le fichier "bdd.db"  

-----------------
## Notifications par SMS

Pour que le système de notification par SMS soit fonctionnel il faut créer un compte [Vonage](https://www.vonage.ca/en/communications-apis/sms/) et récupérer la 'key' et le 'secret' associé à votre compte. Il faut ensuite les indiquer au début
du fichier 'app.py' dans les variables VONAGE_KEY et VONAGE_SECRET.

-----------------
## Notifications par Mail

Pour que le système de notification par mail soit fonctionnel, il faut modifier la variable 'SENDER' dans le début du fichier 'mail.py' situé dans le dossier '/server/notifications/' pour y mettre votre email Gmail. Ensuite, la première fois qu'un mail sera envoyé il sera demandé de se connecter à ce compte Gmail.

-----------------
## Lancement du serveur web

Pour lancer le serveur web lancez la commande suivante :
```bash
flask run
```
Ensuite vous pourrez accéder à l'interface web à l'adresse [127.0.0.1:5000](127.0.0.1:5000)  
Voici les comptes par défaut disponible :  

| Nom d'utilisateur | Mot de passe | Est administrateur |
| --- | --- | --- |
| `user1` | `test` | &check; |
| `Pierre` | `test` | &check; |
| `Olivier` | `test` | &#x2610; |
| `Michel` | `test` | &#x2610; |
| `Jacque` | `test` | &#x2610; |
| `Thomas` | `test` | &#x2610; |
| `Théo` | `test` | &#x2610; |
| `Didier` | `test` | &#x2610; |
| `Alexandre` | `test` | &#x2610; |
| `François` | `test` | &check; |

Un jeu de données de test est également accessible en décompressant le fichier 'donnees.zip'.

-----------------
## Fonctionnalités

-----------------
#### Gestion des utilisateurs

    - Page d'enregistrement et de connexion pour les utilisateurs non connectés
    - Possibilité d'accéder aux informations de votre profil une fois connecté
    - Page pour changer les informations associées à votre compte
    - Page administrateur permettant de modifier les informations des différents utilisateurs
    
-----------------
#### Gestion des objets

    - Chaque objet a un propriétaire associé qui choisi qui a le droit d'intéragir avec son objet
    - Chaque utilisateur a le droit de rajouter de nouveaux objets
    - Il est possible de modifier le propriétaire d'un objet uniquement si on est son propriétaire actuel ou si on est administrateur
    - L'utilisateur peut définir les méthodes de notifications préférées pour chaque objet auquel il a accès
    - L'utilisateur ne peut soumettre des données pour un objet que si il a le droit d'intéragir avec
    - Chaque objet possède un historique des attaques détectées récentes
    
-----------------
#### Analyse des données

    - Il est possible d'analyser des données énergétiques et réseau pour un objet
    - Les données sont prétraitées et ensuite analysées par un modèle de machine learning afin de détecter le type de comportement
    - Le résultat est ensuite affiché à l'utilisateur qui a analysé les données
    - En cas de comportement anormal (+ de 5% de comportement anormal) les utilisateurs associés à l'objet sont notifiés
    
-----------------
## Membres

    - Alexis Vandemoortele
    - Erwan Renault
    - Georges-Pascal Kossi BINESSI
    - Théo Boulogne
    - Théo Dubois
    - Thomas Deruy
    
-----------------

# 2023

-----------------
