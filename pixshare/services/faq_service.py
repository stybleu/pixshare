"""Questions fréquentes. Les chiffres viennent des réglages : la page reste juste quand l'admin les change."""
from __future__ import annotations


def faq() -> list[dict]:
    from pixshare.services.settings_service import get_support_url, limits_table

    lim = limits_table()
    guest, member = lim["guest"], lim["member"]
    albums = lim.get("albums")
    sections = [
        ("Envoyer une photo", [
            ("Faut-il créer un compte pour envoyer une image ?",
             f"Non. Vous pouvez envoyer une photo ou une vidéo sans inscription, gardée jusqu'à {guest['life']}, "
             f"{guest['mb']} Mo au maximum. Un compte gratuit permet d'aller plus loin.", []),
            ("Quels formats sont acceptés ?",
             "Les images JPG, PNG, GIF, WebP, HEIC (photos d'iPhone), TIFF et BMP, et les vidéos MP4, WebM, MOV et AVI.", []),
            ("Quelle est la taille maximale d'une photo ou d'une vidéo ?",
             f"{guest['mb']} Mo sans compte, et {member['mb']} Mo avec un compte gratuit.", []),
            ("Combien de temps ma photo reste-t-elle en ligne ?",
             f"Le temps que vous choisissez au moment de l'envoi : jusqu'à {guest['life']} sans compte, "
             f"et jusqu'à {member['life']} avec un compte gratuit. Ensuite, elle est supprimée automatiquement. "
             "Si une image doit d'abord être vérifiée, le compte à rebours ne commence qu'après la vérification.", []),
            ("Mes photos perdent-elles en qualité ?",
             "Non : vos images ne sont pas recompressées. Seules les informations cachées (position GPS, modèle "
             "d'appareil, date) sont retirées pour protéger votre vie privée. Vous pouvez aussi redimensionner "
             "une image avant l'envoi, si vous le souhaitez.", []),
        ]),
        ("Partager", [
            ("Comment partager mon image ?",
             "Après l'envoi, PixShare vous donne un lien à copier, ainsi que des codes prêts à coller pour les "
             "forums, les sites, Discord ou Markdown. Vous les retrouvez à tout moment dans « Mes envois », "
             "sur la page d'accueil.", []),
            ("Puis-je protéger mon image par un mot de passe ?",
             "Oui, avec un compte gratuit. Vous pouvez aussi faire supprimer l'image automatiquement après un "
             "nombre de vues choisi.", []),
            ("Comment supprimer ma photo avant la fin ?",
             "Dans « Mes envois », sur la page d'accueil, depuis le navigateur qui a servi à l'envoyer. "
             "Avec un compte, vous pouvez le faire depuis n'importe lequel de vos appareils.", []),
            ("Puis-je remplacer une image sans changer le lien ?",
             "Oui, avec un compte gratuit : la nouvelle image prend la place de l'ancienne, et le lien déjà "
             "partagé continue de fonctionner.", []),
        ]),
        ("Compte gratuit", [
            ("Qu'apporte un compte gratuit ?",
             f"Des photos et vidéos gardées jusqu'à {member['life']} et jusqu'à {member['mb']} Mo, vos images sur tous vos "
             "appareils, le mot de passe et la limite de vues, l'amélioration des photos, le remplacement sans "
             "changer le lien, l'extension pour navigateur"
             + (", et les albums souvenirs à partager par QR code." if albums else "."),
             [("Créer un compte", "account.signup")]),
            ("Comment supprimer mon compte ?",
             "Dans « Mon compte », en bas de la page : « Supprimer mon compte ». Toutes vos photos, vos vidéos et vos albums "
             "sont alors supprimés, définitivement.", []),
        ]),
    ]
    if albums:
        sections.append(("Albums souvenirs", [
            ("Comment créer un album pour un mariage ou une fête ?",
             "Avec un compte gratuit, ouvrez « Mes albums », donnez un nom à l'album et choisissez le style de "
             "votre événement. Partagez ensuite le QR code : vos invités voient les photos et ajoutent les leurs, "
             "sans application ni inscription.",
             [("Découvrir les albums souvenirs", "public.albums_info")]),
        ]))
    sections.append(("Confidentialité et sécurité", [
        ("Qui peut voir mes images ?",
         "Uniquement les personnes à qui vous donnez le lien. Vos images ne sont listées nulle part sur le site.", []),
        ("Mes images apparaissent-elles sur Google ?",
         "Non. Vos photos, vos vidéos et vos albums n'apparaissent pas dans les résultats de Google : le site "
         "demande aux moteurs de recherche de ne pas les référencer. Seules les personnes qui ont le lien peuvent "
         "les voir.", []),
        ("Pourquoi mon image a-t-elle été refusée ou supprimée ?",
         "Les images sont vérifiées automatiquement : la nudité, la pornographie et les contenus illégaux sont "
         "interdits par les conditions d'utilisation. Une image douteuse peut être mise de côté pour vérification, "
         "ou supprimée. Dans ce cas, un message vous indique laquelle et pourquoi, et elle reste indiquée "
         "7 jours dans « Mes envois ». Avec un compte, ce message vous suit sur tous vos appareils, et vous "
         "pouvez remplacer l'image par une autre en gardant le même lien. Une image déjà interdite (même "
         "renommée ou redimensionnée) ne peut pas être republiée.", [("Lire les conditions d'utilisation", "public.cgu")]),
        ("Comment signaler un contenu ?",
         "Avec le bouton « Signaler » sous chaque image, ou par le formulaire de contact. Les signalements sont "
         "vérifiés, et une image signalée peut être masquée en attendant la vérification.", [("Formulaire de contact", "public.contact")]),
        ("Peut-on installer PixShare sur son téléphone ?",
         "Oui. Sur Android, dans Chrome ou Samsung Internet, ouvrez le menu du navigateur puis « Installer l'application » "
         "(ou « Ajouter à l'écran d'accueil »). PixShare apparaît alors dans le menu « Partager » de votre galerie : "
         "choisissez une photo, « Partager », puis PixShare, et elle arrive directement dans le formulaire d'envoi. "
         "Sur iPhone, « Ajouter à l'écran d'accueil » fonctionne aussi, mais Safari ne permet pas encore le partage "
         "depuis la galerie. Sur ordinateur, vous pouvez aussi coller une capture d'écran avec Ctrl+V, ou envoyer "
         "jusqu'à 10 photos d'un coup.", []),
        ("Pourquoi me demande-t-on un code par mail à la connexion ?",
         "Pour protéger votre compte et vos albums : sur un appareil ou un navigateur que le site ne connaît pas encore, "
         "le bon mot de passe ne suffit pas, il faut aussi le code à 6 chiffres reçu par mail. Ensuite, cet appareil est "
         "reconnu et le code n'est plus demandé. Vous pouvez voir et retirer vos appareils dans « Mon compte ». "
         "Si vous recevez un code sans l'avoir demandé, quelqu'un connaît votre mot de passe : utilisez le bouton "
         "« Ce n'était pas moi » du mail.", []),
        ("Le site utilise-t-il des cookies de pistage ?",
         "Non. PixShare n'utilise que des cookies techniques, nécessaires au fonctionnement du site (sécurité, "
         "connexion, historique de vos envois), sans publicité ni mesure d'audience.",
         [("Mentions légales", "public.mentions_legales")]),
        ("Le service est-il payant ?",
         "Non, PixShare est gratuit et sans publicité."
         + (" Si vous souhaitez soutenir le site, vous pouvez faire un don." if get_support_url() else ""),
         [("☕ Soutenir PixShare", get_support_url())] if get_support_url() else []),
    ]))
    return [{"title": title, "items": [{"q": q, "a": a, "links": links} for q, a, links in items]}
            for title, items in sections]
