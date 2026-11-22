"""Titre et description propres à chaque page publique (en français et en anglais).

Les outils d'analyse (Google, IONOS…) veulent un titre de 30 à 60 caractères et une description
de 120 à 160 caractères, différents d'une page à l'autre. L'accueil garde ses textes de traduction.
"""
from __future__ import annotations

PAGES = {
    "public.contact": {
        "fr": ("Contact – PixShare, hébergeur d'images gratuit",
               "Une question, un souci ou un contenu à signaler ? Écrivez à l'équipe de PixShare avec le "
               "formulaire de contact : nous vous répondons rapidement, en français."),
        "en": ("Contact us – PixShare, free image hosting",
               "A question, a problem or content to report? Write to the PixShare team using the contact "
               "form and we will get back to you quickly."),
    },
    "public.cgu": {
        "fr": ("Conditions générales d'utilisation – PixShare",
               "Les règles de PixShare : contenus autorisés, durée de conservation des images, modération, "
               "comptes gratuits, albums souvenirs, signalements et vos droits."),
        "en": ("Terms of use – PixShare free image hosting",
               "PixShare rules: allowed content, how long images are kept, moderation, free accounts, "
               "memory albums, reports and your rights."),
    },
    "public.mentions_legales": {
        "fr": ("Mentions légales et hébergeur du site – PixShare",
               "Mentions légales de PixShare : éditeur du site, hébergement, contact, données personnelles, "
               "propriété intellectuelle et signalement d'un contenu illicite."),
        "en": ("Legal notice and site host – PixShare",
               "PixShare legal notice: site publisher, hosting provider, contact details, personal data, "
               "intellectual property and how to report illegal content."),
    },
    "public.faq": {
        "fr": ("Questions fréquentes sur l'hébergement d'images – PixShare",
               "Formats acceptés, taille maximale, durée de conservation, partage, mot de passe, compte gratuit, "
               "albums souvenirs et confidentialité : les réponses."),
        "en": ("Frequently asked questions about image hosting – PixShare",
               "PixShare FAQ: accepted formats, maximum size, how long files are kept, sharing, passwords, "
               "free accounts, memory albums and privacy."),
    },
    "public.albums_info": {
        "fr": ("Album photo de mariage partagé par QR code – PixShare",
               "Mariage, anniversaire, baptême : un album photo partagé par QR code où vos invités ajoutent "
               "leurs photos, sans application ni inscription."),
        "en": ("Wedding photo album shared by QR code – PixShare",
               "Wedding, birthday, christening, party: gather every memory of your event in a photo album shared "
               "with a QR code. Your guests add their photos, no app needed."),
    },
    "account.login": {
        "fr": ("Connexion à votre compte gratuit – PixShare",
               "Connectez-vous à votre compte PixShare gratuit pour retrouver vos images sur tous vos appareils, "
               "vos albums souvenirs et toutes vos options."),
        "en": ("Log in to your free account – PixShare",
               "Log in to your free PixShare account to find your images on all your devices, your memory "
               "albums and all your options."),
    },
    "account.signup": {
        "fr": ("Créer un compte gratuit PixShare : photos et albums",
               "Créez un compte PixShare gratuit : photos gardées plus longtemps, mot de passe, filtres, albums "
               "souvenirs partagés par QR code et vos images sur tous vos appareils."),
        "en": ("Create a free PixShare account: photos and albums",
               "Create a free PixShare account: photos kept longer, passwords, filters, memory albums shared by "
               "QR code and your images on all your devices."),
    },
    "account.forgot": {
        "fr": ("Mot de passe oublié : le réinitialiser – PixShare",
               "Mot de passe oublié ? Recevez par e-mail un lien sécurisé pour en choisir un nouveau et "
               "retrouver l'accès à votre compte PixShare gratuit."),
        "en": ("Forgot your password? Reset it – PixShare",
               "Forgot your password? Get a secure link by email to choose a new one and get back into your "
               "free PixShare account."),
    },
}


def page_seo(endpoint: str | None, lang: str | None) -> dict | None:
    entry = PAGES.get(endpoint or "")
    if not entry:
        return None
    title, desc = entry.get(lang or "fr") or entry["fr"]
    return {"title": title, "desc": desc}
