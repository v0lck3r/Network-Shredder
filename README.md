# Network-Shredder
Network-Shredder est un IDS écrit en Python.
![](./source/static/logo.png)
# TODO LIST

+ PCAP Mod : DONE
+ Design Console : DONE
+ Web Application (Table (matched packet, rule)) : DONE
+ Create a requirement file : DONE
+ Quite mode in condole : DONE
+ Customize the options and Customize the rules to detect attacks such as arp spoofing, ddos,... : DONE
---------

- Create the report


### Options : 

- msg - affiche un message dans les alertes et journalise les paquets

- content - recherche un motif dans la charge d'un paquet

- offset - modifie l'option content, fixe le décalage du début de la tentative de correspondance de
motif

- ttl - teste la valeur du champ TTL de l'entête IP

- dsize - teste la taille de la charge du paquet contre une valeur

- flags - teste les drapeaux TCP pour certaines valeurs

- seq - teste le champ TCP de numéro de séquence pour une valeur spécifique

- ack - teste le champ TCP d'acquittement pour une valeur spécifiée

