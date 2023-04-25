from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from server.db.getdb import getUsers, getObjets, addHistorique
import pandas as pd
import pickle
import numpy as np
import vonage
import os
from server.notifications.mail import send_email
import time
import re
from keras.models import load_model
from flask import current_app

from sklearn.metrics import accuracy_score
import hashlib

np.random.seed(2)

import pickle




# Fonction pour convertir le hash SHA256 en 4 entiers
def hash_to_ints(hash_str):
    # Convertir le hash en un tableau d'octets
    hash_bytes = bytearray.fromhex(hash_str)
    # Convertir les 4 premiers octets en entiers
    ints = [int.from_bytes(hash_bytes[i:i+4], byteorder='big') for i in range(4)]
    return ints

def is_valid_ip(str):
    # expression régulière pour une adresse IP valide
    pattern = '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # vérifier si la chaîne de caractères correspond à l'expression régulière
    if re.match(pattern, str):
        return True
    else:
        return False
    
# Fonction pour traiter une adresse IP
def process_ip(ip):
    if pd.isnull(ip):
        return pd.Series([0, 0, 0, 0])
    if is_valid_ip(ip):
        # Si l'adresse IP est sous forme de quatre parties séparées par des points
        return pd.Series(ip.split('.'))
    else:
        # Si l'adresse IP est sous une autre forme, la hasher avec SHA256 et la convertir en 4 entiers
        hash_str = hashlib.sha256(ip.encode('utf-8')).hexdigest()
        ints = hash_to_ints(hash_str)
        return pd.Series(ints)


def Analyse(objet_id, power_file, wireshark_file):

    contactids = []
    objetIndex = -1
    objets = getObjets()
    for i in range(len(objets)):
        if str(objets[i]["id"]) == objet_id:
            objetIndex = i
            contactids = objets[i]["users"].split(";")


    
    # Récupération des contacts
    contacts = getUsers()
    contact_list = []
    for i in range(len(contacts)):
        if (contacts[i]["id"] in objets[objetIndex]["acces"].split(";")) or contacts[i]["admin"] == "1":
            for j in range(len(contactids)):
                if str(contacts[i]["id"]) == contactids[j].split(':')[0]:
                    contact_list.append({"contact":contacts[i], "email":contactids[j].split(':')[1] == "1", "sms":contactids[j].split(':')[2] == "1"})





    elem_percent_sorted = []



    #if(power_file != ""):
    #    # Open the input and output files
    #    with open("server/uploads/unprepared/" + power_file , 'rb') as infile, open("server/uploads/prepared/" + power_file, 'w', newline='', encoding='utf-8') as outfile:
    #        # Read the input file as binary and decode the contents as UTF-16 LE
    #        content = infile.read().decode('utf-16-le')
    #        # Remove null bytes
    #        content = content.replace('\x00', '')
    #        
    #        reader = csv.reader(content.splitlines())
    #        writer = csv.writer(outfile)
    #        
    #        headers = next(reader)  # Save the header row
    #        writer.writerow(headers)  # Write the header row to the output file
    #        
    #        for row in reader:
    #            writer.writerow(row)
    #    os.remove(os.path.join("server/uploads/unprepared/", power_file))
    

    #if(wireshark_file != ""):
    #    # Open the input and output files
    #    with open("server/uploads/unprepared/" + wireshark_file , 'rb') as infile, open("server/uploads/prepared/" + wireshark_file, 'w', newline='', encoding='utf-8') as outfile:
    #        # Read the input file as binary and decode the contents as UTF-16 LE
    #        content = infile.read().decode('utf-16-le')
    #        # Remove null bytes
    #        content = content.replace('\x00', '')
    #        
    #        reader = csv.reader(content.splitlines())
    #        writer = csv.writer(outfile)
    #        
    #        headers = next(reader)  # Save the header row
    #        writer.writerow(headers)  # Write the header row to the output file
    #        
    #        for row in reader:
    #            writer.writerow(row)
    #    os.remove(os.path.join("server/uploads/unprepared/", wireshark_file))





    listeProtocols = ['0x8011', 'ICMPv6', 'CLASSIC-STUN', 'HTTP/XML', 'QUIC', 'GQUIC', 'IRC', 'IP', 'RTCP' , 'IGMPv2', 'DHCP', 'SSDP', 'ICMP', 'TCP', 'MDNS', 'TLSv1.2', 'IPv4', 'SNA', 'LLC', '802.11', 'IGMPv0', 'HTTP', 'DNS', 'ARP', 'CLNP', 'SSL', 'TLSv1.3', 'SSLv2', 'NTP', 'NBNS', 'IGMP']


    colonnesProtocols = ['Protocol_802.11',
        'Protocol_0x8011','Protocol_CLASSIC-STUN','Protocol_HTTP/XML',
        'Protocol_QUIC','Protocol_GQUIC','Protocol_IRC', 'Protocol_ICMPv6',
        'Protocol_IP','Protocol_RTCP',
        'Protocol_ARP', 'Protocol_CLNP', 'Protocol_DHCP', 'Protocol_DNS',
        'Protocol_HTTP', 'Protocol_ICMP', 'Protocol_IGMP', 'Protocol_IGMPv0',
        'Protocol_IGMPv2', 'Protocol_IPv4', 'Protocol_LLC', 'Protocol_MDNS',
        'Protocol_NBNS', 'Protocol_NTP', 'Protocol_SNA', 'Protocol_SSDP',
        'Protocol_SSL', 'Protocol_SSLv2', 'Protocol_TCP', 'Protocol_TLSv1.2',
        'Protocol_TLSv1.3']

    # Reseau
    if(power_file == ""):
        # réseau only

        colonnesAGarder = ['Time', 'Length', 'IP_Source_1', 'IP_Source_2',
       'IP_Source_3', 'IP_Source_4', 'IP_Destination_1', 'IP_Destination_2',
       'IP_Destination_3', 'IP_Destination_4', 'Protocol_802.11',
       'Protocol_0x8011','Protocol_CLASSIC-STUN','Protocol_HTTP/XML',
       'Protocol_QUIC','Protocol_GQUIC','Protocol_IRC','Protocol_ICMPv6',
       'Protocol_IP','Protocol_RTCP',
       'Protocol_ARP', 'Protocol_CLNP', 'Protocol_DHCP', 'Protocol_DNS',
       'Protocol_HTTP', 'Protocol_ICMP', 'Protocol_IGMP', 'Protocol_IGMPv0',
       'Protocol_IGMPv2', 'Protocol_IPv4', 'Protocol_LLC', 'Protocol_MDNS',
       'Protocol_NBNS', 'Protocol_NTP', 'Protocol_SNA', 'Protocol_SSDP',
       'Protocol_SSL', 'Protocol_SSLv2', 'Protocol_TCP', 'Protocol_TLSv1.2',
       'Protocol_TLSv1.3', 'Length_10s_min', 'Length_10s_max',
       'Length_10s_median', 'Length_10s_mean', 'Length_10s_var',
       'Length_1m_min', 'Length_1m_max', 'Length_1m_median', 'Length_1m_mean',
       'Length_1m_var', 'Length_10m_min', 'Length_10m_max',
       'Length_10m_median', 'Length_10m_mean', 'Length_10m_var'
     ]

            
        # Lis le fichier csv de réseau
        data = (pd.read_csv("server/uploads/prepared/" + wireshark_file, warn_bad_lines=False, error_bad_lines=False))
        

        # Appliquer la fonction de traitement aux colonnes "Source" et "Destination"
        data[['IP_Source_1', 'IP_Source_2', 'IP_Source_3', 'IP_Source_4']] = data['Source'].apply(process_ip)
        data[['IP_Destination_1', 'IP_Destination_2', 'IP_Destination_3', 'IP_Destination_4']] = data['Destination'].apply(process_ip)


        # Créer les colonnes avec l'encodage One-Hot pour les protocoles supportés
        data[colonnesProtocols] = 0
        dummiestmp = pd.get_dummies(data["Protocol"], columns=listeProtocols, prefix="Protocol")

        # Fusionner les colonnes encodées avec le dataset initial
        data[dummiestmp.columns] = dummiestmp

        # Définir la colonne "Time_Index" comme indice à partir de la colonne "Time"
        data["Time_Index"] = data["Time"]
        data["Time_Index"] = pd.to_datetime(data["Time_Index"], unit='ms')
        data.set_index("Time_Index", inplace=True)
        data = data.sort_index()



        ToStat = ["Length"]
        for j in range(len(ToStat)):

            # Calculer les statistiques pour chaque fenêtre de 10 secondes
            rolling_stats_10s = data.rolling("10s").agg({
                f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
            })
            rolling_stats_10s.columns = [f"{col}_10s_{stat}" for col, stat in rolling_stats_10s.columns]
            rolling_stats_10s[f"{ToStat[j]}_10s_var"] = rolling_stats_10s[f"{ToStat[j]}_10s_var"].fillna(0)

            # Calculer les statistiques pour chaque fenêtre de 1 minute
            rolling_stats_1m = data.rolling("1min").agg({
                f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
            })
            rolling_stats_1m.columns = [f"{col}_1m_{stat}" for col, stat in rolling_stats_1m.columns]
            rolling_stats_1m[f"{ToStat[j]}_1m_var"] = rolling_stats_1m[f"{ToStat[j]}_1m_var"].fillna(0)

            # Calculer les statistiques pour chaque fenêtre de 10 minutes
            rolling_stats_10m = data.rolling("10min").agg({
                f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
            })
            rolling_stats_10m.columns = [f"{col}_10m_{stat}" for col, stat in rolling_stats_10m.columns]
            rolling_stats_10m[f"{ToStat[j]}_10m_var"] = rolling_stats_10m[f"{ToStat[j]}_10m_var"].fillna(0)

            # Concaténer les colonnes de statistiques avec le dataset initial
            data = pd.concat([data , rolling_stats_10s, rolling_stats_1m, rolling_stats_10m], axis=1)
        
        # On supprime toutes les colonnes en trop
        data = data[colonnesAGarder]

        

        
        data = np.asarray(data).astype(np.float32)
        
        print('load reseau model')
        model = load_model('server/ml/entrainement/entrainementReseau')
        print('loaded reseau model')

        predictions = model.predict(data)

        # Créer une liste de labels de catégorie
        labels = ["normal","DoS","RTSP"]

        # Trouver l'indice de la catégorie avec la plus haute probabilité pour chaque ligne
        max_indices = np.argmax(predictions, axis=1)

        # Utiliser les indices pour récupérer les labels correspondants
        categories = [labels[idx] for idx in max_indices]

        # Compter le nombre d'occurrences de chaque catégorie
        unique, counts = np.unique(categories, return_counts=True)

        # Calculer le pourcentage d'apparition de chaque catégorie
        percentages = np.round(100 * counts / len(categories), 2)

        # Créer une liste de tuples (catégorie, pourcentage)
        cat_percent = list(zip(unique, percentages))

        # Trier la liste en fonction du pourcentage (du plus grand au plus petit)
        elem_percent_sorted = sorted(cat_percent, key=lambda x: x[1], reverse=True)
        os.remove(os.path.join("server/uploads/prepared/", wireshark_file))
        
    # NRJ
    elif(wireshark_file == ""):
        # power only

        colonnesAGarder = [ 'time_energy',
       'voltage_10s_min', 'voltage_10s_max', 'voltage_10s_median',
       'voltage_10s_mean', 'voltage_10s_var', 'voltage_1m_min',
       'voltage_1m_max', 'voltage_1m_median', 'voltage_1m_mean',
       'voltage_1m_var', 'voltage_10m_min', 'voltage_10m_max',
       'voltage_10m_median', 'voltage_10m_mean', 'voltage_10m_var']
        

        with open('server/ml/entrainement/entrainementEnergie.pkl', "rb") as f:
            print('load nrj model')
            model = pickle.load(f)
            print('loaded nrj model')

            data = (pd.read_csv("server/uploads/prepared/" + power_file,sep=';', warn_bad_lines=False, error_bad_lines=False, decimal=',', header=None, names=["time_energy", "voltage"]))
            
            
            data.sort_values("time_energy")

            # Définir la colonne "Time_Index" comme indice à partir de la colonne "Time"
            data["Time_Index"] = data["time_energy"]
            data["Time_Index"] = pd.to_datetime(data["Time_Index"])
            data.set_index("Time_Index", inplace=True)

            ToStat = ["voltage"]
            for j in range(1):

                # Calculer les statistiques pour chaque fenêtre de 10 secondes
                rolling_stats_10s = data.rolling("10s").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_10s.columns = [f"{col}_10s_{stat}" for col, stat in rolling_stats_10s.columns]
                rolling_stats_10s[f"{ToStat[j]}_10s_var"] = rolling_stats_10s[f"{ToStat[j]}_10s_var"].fillna(0)

                # Calculer les statistiques pour chaque fenêtre de 1 minute
                rolling_stats_1m = data.rolling("1min").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_1m.columns = [f"{col}_1m_{stat}" for col, stat in rolling_stats_1m.columns]
                rolling_stats_1m[f"{ToStat[j]}_1m_var"] = rolling_stats_1m[f"{ToStat[j]}_1m_var"].fillna(0)

                # Calculer les statistiques pour chaque fenêtre de 10 minutes
                rolling_stats_10m = data.rolling("10min").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_10m.columns = [f"{col}_10m_{stat}" for col, stat in rolling_stats_10m.columns]
                rolling_stats_10m[f"{ToStat[j]}_10m_var"] = rolling_stats_10m[f"{ToStat[j]}_10m_var"].fillna(0)

                # Concaténer les colonnes de statistiques avec le dataset initial
                data = pd.concat([data , rolling_stats_10s, rolling_stats_1m, rolling_stats_10m], axis=1)
            
            data = data[colonnesAGarder]

            # Prédiction du modèle
            predictions = model.predict(data)
            
            # calcul du pourcentage de 1 dans chaque colonne
            percentages = [(col, np.mean(predictions[:,col])*100) for col in range(predictions.shape[1])]
            percentages[0] = ("Normal", percentages[0][1])
            percentages[1] = ("Anormal", percentages[1][1])

            # Trier la liste en fonction du pourcentage (du plus grand au plus petit)
            elem_percent_sorted = sorted(percentages, key=lambda x: x[1], reverse=True)

            os.remove(os.path.join("server/uploads/prepared/", power_file))

    # Both
    else:
        # les deux

        
        with open('server/ml/entrainement/entrainementBIS.pkl', "rb") as f:
            print('load bis model')
            model = pickle.load(f)
            print('loaded bis model')


            colonnesAGarder = ['Time', 'Length', 'voltage', 'IP_Source_1', 'IP_Source_2',
       'IP_Source_3', 'IP_Source_4', 'IP_Destination_1', 'IP_Destination_2',
       'IP_Destination_3', 'IP_Destination_4', 'Protocol_802.11',
       'Protocol_0x8011','Protocol_CLASSIC-STUN','Protocol_HTTP/XML',
       'Protocol_QUIC','Protocol_GQUIC','Protocol_IRC','Protocol_ICMPv6',
       'Protocol_IP','Protocol_RTCP',
       'Protocol_ARP', 'Protocol_CLNP', 'Protocol_DHCP', 'Protocol_DNS',
       'Protocol_HTTP', 'Protocol_ICMP', 'Protocol_IGMP', 'Protocol_IGMPv0',
       'Protocol_IGMPv2', 'Protocol_IPv4', 'Protocol_LLC', 'Protocol_MDNS',
       'Protocol_NBNS', 'Protocol_NTP', 'Protocol_SNA', 'Protocol_SSDP',
       'Protocol_SSL', 'Protocol_SSLv2', 'Protocol_TCP', 'Protocol_TLSv1.2',
       'Protocol_TLSv1.3', 'Length_10s_min', 'Length_10s_max',
       'Length_10s_median', 'Length_10s_mean', 'Length_10s_var',
       'Length_1m_min', 'Length_1m_max', 'Length_1m_median', 'Length_1m_mean',
       'Length_1m_var', 'Length_10m_min', 'Length_10m_max',
       'Length_10m_median', 'Length_10m_mean', 'Length_10m_var',
       'voltage_10s_min', 'voltage_10s_max', 'voltage_10s_median',
       'voltage_10s_mean', 'voltage_10s_var', 'voltage_1m_min',
       'voltage_1m_max', 'voltage_1m_median', 'voltage_1m_mean',
       'voltage_1m_var', 'voltage_10m_min', 'voltage_10m_max',
       'voltage_10m_median', 'voltage_10m_mean', 'voltage_10m_var']

            dataEnergie = (pd.read_csv("server/uploads/prepared/" + power_file,sep=';', warn_bad_lines=False, error_bad_lines=False, decimal=',', header=None, names=["time_energy", "voltage"]))
            
            
            # Lis le fichier csv de réseau
            dataReseau = (pd.read_csv("server/uploads/prepared/" + wireshark_file, warn_bad_lines=False, error_bad_lines=False))
            

            # Interpole le temps de la capture énergétique a partir de la capture réseau
            dataEnergie["time_energy"] = np.linspace(0, dataReseau["Time"].max(), len(dataEnergie))

            # Fusionner les deux ensembles de données en utilisant le temps en seconde comme clé
            data = (pd.merge_asof(dataReseau.sort_values("Time"), dataEnergie.sort_values("time_energy"), left_on="Time", right_on="time_energy"))

            # Appliquer la fonction de traitement aux colonnes "Source" et "Destination"
            data[['IP_Source_1', 'IP_Source_2', 'IP_Source_3', 'IP_Source_4']] = data['Source'].apply(process_ip)

            # Appliquer la fonction de traitement aux colonnes "Source" et "Destination"
            data[['IP_Destination_1', 'IP_Destination_2', 'IP_Destination_3', 'IP_Destination_4']] = data['Destination'].apply(process_ip)

            data[colonnesProtocols] = 0

            # Créer les colonnes avec l'encodage One-Hot pour les protocoles supportés
            dummiestmp = pd.get_dummies(data["Protocol"], columns=listeProtocols, prefix="Protocol")

            # Fusionner les colonnes encodées avec le dataset initial
            data[dummiestmp.columns] = dummiestmp

            # Supprimer les colonnes en trop
            data.drop(["No.", "Info", "Protocol", "Source", "Destination", "time_energy"], axis=1, inplace=True)

            # Définir la colonne "Time_Index" comme indice à partir de la colonne "Time"
            data["Time_Index"] = data["Time"]
            data["Time_Index"] = pd.to_datetime(data["Time_Index"])
            data.set_index("Time_Index", inplace=True)


            ToStat = ["Length", "voltage"]
            for j in range(2):

                # Calculer les statistiques pour chaque fenêtre de 10 secondes
                rolling_stats_10s = data.rolling("10s").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_10s.columns = [f"{col}_10s_{stat}" for col, stat in rolling_stats_10s.columns]
                rolling_stats_10s[f"{ToStat[j]}_10s_var"] = rolling_stats_10s[f"{ToStat[j]}_10s_var"].fillna(0)

                # Calculer les statistiques pour chaque fenêtre de 1 minute
                rolling_stats_1m = data.rolling("1min").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_1m.columns = [f"{col}_1m_{stat}" for col, stat in rolling_stats_1m.columns]
                rolling_stats_1m[f"{ToStat[j]}_1m_var"] = rolling_stats_1m[f"{ToStat[j]}_1m_var"].fillna(0)

                # Calculer les statistiques pour chaque fenêtre de 10 minutes
                rolling_stats_10m = data.rolling("10min").agg({
                    f"{ToStat[j]}": ["min", "max", "median", "mean", "var"]
                })
                rolling_stats_10m.columns = [f"{col}_10m_{stat}" for col, stat in rolling_stats_10m.columns]
                rolling_stats_10m[f"{ToStat[j]}_10m_var"] = rolling_stats_10m[f"{ToStat[j]}_10m_var"].fillna(0)

                # Concaténer les colonnes de statistiques avec le dataset initial
                data = pd.concat([data , rolling_stats_10s, rolling_stats_1m, rolling_stats_10m], axis=1)
            
            data = data[colonnesAGarder]

            # Prédiction du modèle
            predictions = model.predict(data)

            # Compter le nombre d'occurrences de chaque élément
            unique, counts = np.unique(predictions, return_counts=True)

            # Calculer le pourcentage d'apparition de chaque élément
            percentages = np.round(100 * counts / len(predictions), 2)

            # Créer une liste de tuples (élément, pourcentage)
            elem_percent = list(zip(unique, percentages))

            # Trier la liste en fonction du pourcentage (du plus grand au plus petit)
            elem_percent_sorted = sorted(elem_percent, key=lambda x: x[1], reverse=True)

            os.remove(os.path.join("server/uploads/prepared/", power_file))
            os.remove(os.path.join("server/uploads/prepared/", wireshark_file))


    # Afficher le résultat et regarder si le comportement est anormal
    comportementNormal = False
    messageRenvoye = "Resultats : "
    for elem, percent in elem_percent_sorted:
        messageRenvoye += ";" + str(elem) + ":" + percent.astype(str)
        if str(elem) == "normal":
            if(power_file == ""):
                if (percent>75): # on garde 25% de marge d'erreur sans l'energie
                    comportementNormal = True
            elif(percent>95): # On garde 5% de marge d'erreur avec l'énergie
                comportementNormal = True




    
    flash(messageRenvoye)

    # Si comportement anormal alors on notifie

    if not comportementNormal:

        # ajout à l'historique
        if objet_id != "-1":
            contenuHistorique = str(int(time.time() * 1000)) + ":"
            for elem, percent in elem_percent_sorted:
                contenuHistorique += " " + str(elem).capitalize() + " à " + str(int(percent)) + "%,"
            print('contenu histo')
            print(contenuHistorique)
            addHistorique(objet_id, contenuHistorique[:-1])

        # rédaction du message 

        
        contenuMessage = ""

        if(len(elem_percent_sorted)==1) :


            contenuMessage = ",\n\n\
Un comportement anormal a été détecter à la suite de l'analyse énergétique et réseau de votre appareil '" + objets[objetIndex]["nom"] + "'. \n\
Il semblerait qu'il s'agit d'un comportement de type : "
        
            for elem, percent in elem_percent_sorted:
                contenuMessage += str(elem).capitalize() + "\n"

        else:
            contenuMessage = ",\n\n\
Un comportement anormal a été détecter à la suite de l'analyse énergétique et réseau de votre appareil '" + objets[objetIndex]["nom"] + "'. \n\
Voici les probabilités de comportement détecté :\n"
        
            for elem, percent in elem_percent_sorted:
                contenuMessage += "- " + str(elem).capitalize() + " : " + percent.astype(str) + "%\n"

        
        for i in range(len(contact_list)):
            # par mail

            if contact_list[i]["contact"]["email"] != "" and contact_list[i]["email"] == True:

                        
                send_email(contact_list[i]["contact"]["email"], "Anomalie dans le comportement d'un objet IoT", "Bonjour " + contact_list[i]["contact"]["username"] + contenuMessage)


            # par sms

            if contact_list[i]["contact"]["numero"] != "" and contact_list[i]["sms"] == True and current_app.config['VONAGE_KEY']!="":
                
                print("send sms to : " + contact_list[i]["contact"]["numero"])
                
                client = vonage.Client(key=current_app.config['VONAGE_KEY'], secret=current_app.config['VONAGE_SECRET'])
                sms = vonage.Sms(client)

                responseData = sms.send_message(
                    {
                        "from": "IDS IoT",
                        "to": contact_list[i]["contact"]["numero"],
                        "text": "Bonjour " + contact_list[i]["contact"]["username"] + contenuMessage + "\n\n\n",
                    }
                )

                if responseData["messages"][0]["status"] == "0":
                    print("Message sent successfully.")
                else:
                    print(f"Message failed with error: {responseData['messages'][0]['error-text']}")

