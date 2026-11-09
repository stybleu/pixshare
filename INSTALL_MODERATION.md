# Modération automatique des images (NudeNet intégré)

Chaque nouvelle image reste privée (« en attente ») le temps d'être analysée par NudeNet, directement par le site, juste après son envoi. Il n'y a plus de bot séparé.

1. Publie ces modifications sur GitHub : Render installe NudeNet au prochain déploiement (`requirements.txt`).
2. Sur le service web Render, garde `MODERATION_PENDING_IMAGES=1` (valeur par défaut).
3. Envoie une image de test : elle est publiée (ou supprimée) quelques secondes après l'envoi.

Réglages : Admin > Paramètres > « Modération automatique (NudeNet) ». Tant que rien n'est enregistré là, ce sont les variables d'environnement Render qui s'appliquent ; une fois enregistrés, les réglages de l'admin passent en priorité.

| Réglage admin | Variable Render (défaut) | Rôle |
| --- | --- | --- |
| Analyse automatique | `NSFW_AUTO_MODERATION` (`1`) | Désactivée : les images restent en attente |
| Seuil de revue manuelle | `NSFW_REVIEW_THRESHOLD` (`0.60`) | À partir de ce score, l'image reste privée et attend ta décision |
| Seuil de suppression | `NSFW_BLOCK_THRESHOLD` (`0.85`) | À partir de ce score, image supprimée et auteur averti |
| Découpage des grandes images | — (oui) | Vue d'ensemble + 4 morceaux ; « Non » économise le calcul |

La page affiche aussi si NudeNet est installé, le nombre d'images en attente d'analyse et celles « à vérifier », avec un bouton « Analyser maintenant ». Les images à vérifier apparaissent dans Admin > Fichiers avec un aperçu privé et les boutons « Approuver et publier » / « Supprimer ».

Comportement :

* les images fixes d'au moins 800 px sont analysées en vue d'ensemble puis en 4 morceaux qui se recouvrent (NudeNet travaille à 320 px, un petit détail serait sinon perdu) ;
* dans un GIF/APNG/WebP animé, jusqu'à 6 images réparties sont analysées ;
* si NudeNet est absent ou si l'image est illisible, elle n'est jamais publiée : après 3 échecs elle part en revue manuelle ;
* chaque envoi traite au plus 10 images en attente, ce qui résorbe aussi un éventuel arriéré.

Une détection NudeNet n'est pas une qualification juridique. Ajuste les seuils selon les faux positifs observés.
