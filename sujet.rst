================
Analyse Suricata
================

Objectif
========

Le but est la création d'un programme qui prend comme argument un fichier pcap ou un fichier JSON
produit par Suricata et sort un rapport au format texte ou JSON contenant les informations principales
à propos de la trace réseau.

Dans le cas de l'entrée d'un fichier pcap, Suricara sera lancé avec les règles ETOpen pour
produire le JSON analysé par le programme (https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules).


La langue de programmation sera l'anglais et le language de programmation est laissé à la
discrétion de l'étudiant.

Le rendu sera une archive comprenant le code correctement commenté, une documentation de son
utilisation (et de l'installation et de la compilation si nécessaire).
Il incluera également une sortie réalisée sur le fichier pcap
de Malware Traffic Analsyis https://www.malware-traffic-analysis.net/2023/10/31/index.html


On pourra utiliser les informations du livre "The Security Analyst’s Guide to Suricata"
(https://github.com/StamusNetworks/suricata-4-analysts).


Visibilité
==========

0. Déterminer et afficher le timestamp des premières et dernières données contenues dans le fichier

1. Déterminer et afficher si des adresses IP privées sont utilisées dans le pcap

2. Si des adresses IP privées sont utilisées, afficher les réseaux utilisés avec leur netmask.

3. En utilisant les requêtes DNS, afficher la liste des domaines Windows présent dans la trace. Lister également, le controleur de domaine.

4. Afficher le nom des utilisateurs extrait des requêtes SMB et Kerberos

5. Pour les IPs du réseau interne, extraire et afficher les versions probables des systèmes d'exploitation en utilisant les requêtes SMB

6. Afficher les services TCP/IP offert sur le réseau avec leur protocol applicatif ou à défaut leur port. On pourra utiliser les événements de type flow.

Détection des menaces
=====================

0. Lister les signatures uniques ayant alertés sur le pcap

1. En utilisant les metadata des signatures alertant sur le pcap, afficher la liste des malwares détectées

2. Lister les adresses internes impactées par les malwares

3. Extraire et afficher la liste des IOCs (hostname, IPs) associés aux alertes sur les malwares

4. Utiliser la correlation par flow_id et tx_id pour extraire la liste des IOCs (hashes de fichiers) associés aux alertes sur les malwares

Rendu
=====

Le lundi 11 décembre, par mail à el@stamus-networks.com, précisez votre nom dans le sujet et MSSIS

Discord: https://discord.gg/vMQjsu4M et demander à Eric Leblond (ericleblond) de rejoindre MSSIS
