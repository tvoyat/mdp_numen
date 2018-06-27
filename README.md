---
# mdp_numen : Recherche des comptes restés avec mdp initialisés avec Numen.

Image docker basique permettant de retrouver les uid/mail pour les comptes
restés avec mot de passe initialisés avec Numen


## Exportation des données LDIF (si pas déjà fait)

Le mot de passe du Directory Manager est à renseigner dans /root/.secret
Attention au retour chariot final  (echo -n Mot_de_passe >/root/.secret)

    nice -n 10 /var/opt/dsee7/bin/dsconf export -w /root/.secret  o=gouv,c=fr /tmp/export.ldif >/dev/null 2>&1

Temps estimé : environ 1m30

## Identification des comptes vulnérables

    LDIF=/tmp/export.ldif

    docker run -v $LDIF:/outils/export.ldif:ro \
       -it --rm --name test_numen \
       --network=none \
       tvoyat/mdp_numen | tee result.txt

Temps estimé : inférieur à 1 minute

## Résultat
Affichage d'une ligne par entrée trouvée comprend l'uid et l'attribut mail séparés par ";"

## Limitations

Seules les fiches avec uid sont traitées (les cn= non)
Si pas d'adresse mail, affichage de "&lt;PAS_DE_MAIL&gt;"

## Avantages

  - Ne modifie pas les traces de connexions
  - Rapidité
  - Portable
  - Ne surcharge pas les annuaires

## Inconvénients

  - Nécessite un export complet avec mot de passe codés avec crypt/SHA/SSHA
  - Basique
  - Ne supporte pas les liens symboliques pour le fichier d'export
  - Ne traite psa les "alternate address"
