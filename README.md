# project-psi

Il est impératif d'installer dépendances avec les commandes suivantes.
Cette installation nécessite pip.

# Installation des dépendances

python3 -m pip install -r requirements.txt

# Lancer le programme

python3 main.py

# Commandes

[command1,command2] -> une des commandes parmis la liste
{nom} -> le nom de la valeur à donner

Commandes basiques :

connect {pair} : Se connecte à un pair et affiche l’arborescence
download [{nomFichier},{hashFichier}] : Télécharge depuis le pair connecté le fichier avec le nom ou le hash donné 
request {pair} {hash} : Télécharge la donné lié au hash d’un pair
peers : Affiche les pairs valides
print [remote,private] : Affiche l’arborescence distante/locale
refresh peers : Récupère une nouvelle liste des pairs
refresh private : Recalcule l’arborescence locale
exit : Arrête le programme et tous les threads liés

# Exemples

peers

connect jch.irif.fr

download securite.jpeg
download e6435c52b1ac3f21a68fa1967d6e531cefc4bbb57693c4a7bd6572bae007f76d
request jch.irif.fr cedbc38630635d16cf76f58be4903b1eba64c00287fed7de8ae8d9f2bd6bc68b
download documents

print remote 
print private

refresh peers

refresh private

exit