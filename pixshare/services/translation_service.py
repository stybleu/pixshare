from __future__ import annotations

from flask import request, session, url_for

SUPPORTED_LANGS = ("fr", "en")
DEFAULT_LANG = "fr"

TRANSLATIONS = {
    "fr": {
        "home": "Accueil",
        "legal": "Mentions légales",
        "cgu": "Conditions générales d'utilisation",
        "lang_fr": "Français",
        "lang_en": "Anglais",
        "hero_hidden_title": "Héberger une image gratuitement et anonymement avec PixShare",
        "hero_subtitle": "Hébergement d'image gratuit et partage de fichiers temporaire.",
        "admin": "Admin",
        "upload_card_title": "Uploader un fichier (suppression automatique)",
        "max_size_label": "Taille max :",
        "mb": "Mo",
        "by_uploading_you_accept": "En envoyant un fichier, vous acceptez les",
        "cgu_short": "CGU",
        "choose_file": "Choisir un fichier",
        "dropzone_title": "Glisse-dépose votre image ici",
        "dropzone_subtitle": "ou cliquez pour sélectionner un fichier",
        "image_preview": "Aperçu de l'image",
        "resize_before_upload": "Redimensionner avant l'envoi",
        "dimensions_label": "Dimensions",
        "width_px": "Largeur (px)",
        "height_px": "Hauteur (px)",
        "placeholder_width": "ex : 800",
        "placeholder_height": "ex : 600",
        "resize_help": "Modifie une seule dimension : l'autre sera calculée automatiquement pour conserver les proportions.",
        "file_lifetime_default_10": "Durée de vie du fichier, par défaut (10 min)",
        "minutes_5": "5 minutes",
        "minutes_10": "10 minutes",
        "minutes_20": "20 minutes",
        "minutes_30": "30 minutes",
        "hour_1": "1 heure",
        "hours_2": "2 heures",
        "expiration_help": "Le fichier sera supprimé automatiquement après expiration.",
        "keep_no_expiration": "Ne pas supprimer (sans expiration)",
        "keep_option_help": "Option activable selon la configuration du serveur.",
        "upload": "Uploader",
        "history_title": "Historique des fichiers",
        "active_count_suffix": "actif(s)",
        "none": "Aucun",
        "views_suffix": "vue(s)",
        "expires_in": "Expire dans",
        "open": "Ouvrir",
        "download": "Télécharger",
        "delete": "Supprimer",
        "confirm_delete_file": "Supprimer ce fichier ?",
        "public_share_link": "Lien public à partager :",
        "copy": "Copier",
        "no_file_yet": "Aucun fichier. Choisissez-en puis cliquez sur",
        "section_host_image_title": "Héberger une image gratuitement",
        "section_host_image_p1": "PixShare est un service permettant d'héberger une image ou une vidéo gratuitement et sans inscription. Les fichiers peuvent être partagés via un lien sécurisé et sont supprimés automatiquement après expiration.",
        "section_host_image_p2": "Le service permet notamment :",
        "feature_screenshot": "héberger une capture d'écran",
        "feature_share_image": "partager une image rapidement",
        "feature_temporary_file": "envoyer un fichier temporaire",
        "feature_short_video": "partager une vidéo courte",
        "section_share_fast_title": "Partager une image ou un fichier rapidement",
        "section_share_fast_p1": "PixShare permet d'uploader une image, une capture d'écran ou une vidéo courte et de générer un lien de partage sécurisé. Les fichiers sont automatiquement supprimés après expiration afin de garantir la confidentialité.",
        "section_share_fast_p2": "Le service est conçu pour partager facilement :",
        "feature_image": "une image",
        "js_selected_prefix": "Sélectionné : ",
        "js_leave_empty_original": "Laisse vide pour envoyer l'image originale.",
        "js_sent_keeping_ratio": "Image envoyée en",
        "js_fill_width_or_height": "Renseigne une largeur ou une hauteur.",
        "js_image_resized_before_upload": "Image redimensionnée avant envoi en",
        "js_cannot_read_original_dimensions": "Impossible de lire les dimensions originales de l'image.",
        "js_invalid_dimensions": "Dimensions invalides pour le redimensionnement.",
        "js_resizing_in_progress": "Redimensionnement en cours...",
        "js_read_file_error": "Impossible de lire le fichier.",
        "js_load_image_resize_error": "Impossible de charger l'image pour redimensionnement.",
        "contact": "Contact",
        "contact_report": "Signalement",
        "name_optional": "Nom (facultatif)",
        "email_optional": "Email (facultatif)",
        "message": "Message",
        "message_description": "Décrivez votre message ou le problème rencontré...",
        "send": "Envoyer",
        "shared_file_og_title": "Fichier partagé via PixShare",
        "report_pixshare_content": "Signalement contenu PixShare",
        "hosting": "Hébergement",
        "illegal_content_report": "Signalement de contenu illicite",
        "contact_form": "formulaire de contact",
        "legal_hosting_service": "PixShare est un service d’hébergement temporaire de fichiers permettant d’uploader et de partager des fichiers via un lien sécurisé.",
        "legal_contact_help": "Pour toute demande, utilise le ",
        "legal_intro_service": "PixShare est un service d’hébergement temporaire de fichiers.",
        "legal_temp_storage": "Les fichiers envoyés sur PixShare sont stockés de manière temporaire.",
        "legal_no_account": "PixShare ne demande pas la création de compte utilisateur.",
        "legal_not_permanent_storage": "Le service est destiné au partage rapide de fichiers et non au stockage permanent.",
        "service_operation_retention": "Fonctionnement du service et durée de conservation",
        "retention_user_can_choose": "L’utilisateur peut choisir une durée de conservation lors de l’envoi.",
        "retention_max_limited": "La durée maximale est limitée par le service afin de garantir le caractère temporaire de l’hébergement.",
        "retention_auto_delete": "Les fichiers sont supprimés automatiquement après expiration.",
        "retention_not_instant": "La suppression peut ne pas être instantanée (un léger délai technique peut exister).",
        "retention_availability_not_guaranteed": "En raison de contraintes techniques (maintenance, redémarrage du serveur ou limitations de l’hébergement), la disponibilité temporaire des fichiers ne peut être garantie.",
        "browser_resize_notice": "Certaines images peuvent être redimensionnées côté navigateur avant leur envoi afin d’optimiser leur taille et leur affichage.",
        "personal_data": "Données personnelles",
        "security_ip_processing": "Pour des raisons de sécurité et de prévention des abus, certaines données techniques telles que l’adresse IP peuvent être temporairement traitées.",
        "data_used_only_for": "Ces données sont utilisées uniquement afin de :",
        "prevent_service_abuse": "prévenir les abus du service",
        "block_access_malicious": "bloquer l’accès en cas de comportement malveillant",
        "ensure_security_stability": "assurer la sécurité et la stabilité du service",
        "temporary_browser_identifier": "Un identifiant technique temporaire peut également être stocké dans le navigateur afin de permettre l’affichage de l’historique des fichiers envoyés depuis ce navigateur. Cet identifiant n’est pas utilisé pour le suivi publicitaire.",
        "no_profile_no_commercial_use": "Aucune création de profil utilisateur ni exploitation commerciale de ces données n’est réalisée.",
        "responsibility": "Responsabilité",
        "user_responsible_uploaded_files": "L’utilisateur est responsable des fichiers qu’il envoie et de leur conformité aux lois et règlements en vigueur.",
        "legal_host_status": "PixShare agit en qualité d’hébergeur technique au sens de l’article 6-I-2 de la loi n°2004-575 du 21 juin 2004 pour la confiance dans l’économie numérique (LCEN).",
        "editor_not_responsible_user_content": "L’éditeur ne peut être tenu responsable des contenus déposés par les utilisateurs. Toutefois, tout contenu manifestement illicite pourra être supprimé sans préavis et l’accès au service pourra être bloqué en cas d’abus.",
        "legal_illegal_content_intro": "Toute personne estimant qu’un contenu présent sur PixShare est manifestement illicite peut le signaler à l’éditeur du service.",
        "report_via_contact_form": "Le signalement peut être effectué via le",
        "report_message_must_contain": "Le message doit contenir :",
        "report_required_url": "l’adresse URL du contenu concerné",
        "report_required_description": "la description du contenu litigieux",
        "report_required_reasons": "les raisons pour lesquelles le contenu est considéré comme illicite",
        "report_required_contact_details": "les coordonnées de la personne effectuant le signalement",
        "legal_report_action": "Après réception d’un signalement complet, PixShare pourra procéder",
        "legal_report_action_suffix": "à la suppression du contenu concerné dans les meilleurs délais.",
        "site_publisher": "Éditeur du site",
        "publisher_label": "Éditeur",
        "site_version": "Version du site",
        "editing": "Éditeur",
         "contat_info_use": "Utilisez ce formulaire pour contacter PixShare ou signaler un contenu problématique.",
         "contact_type_message": "Type de messages",
         
    },
    
    
    "en": {
        "home": "Home",
        "legal": "Legal notice",
        "cgu": "Terms of use",
        "lang_fr": "French",
        "lang_en": "English",
        "hero_hidden_title": "Host an image for free and anonymously with PixShare",
        "hero_subtitle": "Free image hosting and temporary file sharing.",
        "admin": "Admin",
        "upload_card_title": "Upload a file (automatic deletion)",
        "max_size_label": "Max size:",
        "mb": "MB",
        "by_uploading_you_accept": "By uploading a file, you accept the",
        "cgu_short": "terms",
        "choose_file": "Choose a file",
        "dropzone_title": "Drag and drop your image here",
        "dropzone_subtitle": "or click to select a file",
        "image_preview": "Image preview",
        "resize_before_upload": "Resize before upload",
        "dimensions_label": "Dimensions",
        "width_px": "Width (px)",
        "height_px": "Height (px)",
        "placeholder_width": "e.g. 800",
        "placeholder_height": "e.g. 600",
        "resize_help": "Change only one dimension: the other will be calculated automatically to keep proportions.",
        "file_lifetime_default_10": "File lifetime, default (10 min)",
        "minutes_5": "5 minutes",
        "minutes_10": "10 minutes",
        "minutes_20": "20 minutes",
        "minutes_30": "30 minutes",
        "hour_1": "1 hour",
        "hours_2": "2 hours",
        "expiration_help": "The file will be automatically deleted after expiration.",
        "keep_no_expiration": "Do not delete (no expiration)",
        "keep_option_help": "Option enabled depending on server configuration.",
        "upload": "Upload",
        "history_title": "File history",
        "active_count_suffix": "active",
        "none": "None",
        "views_suffix": "view(s)",
        "expires_in": "Expires in",
        "open": "Open",
        "download": "Download",
        "delete": "Delete",
        "confirm_delete_file": "Delete this file?",
        "public_share_link": "Public link to share:",
        "copy": "Copy",
        "no_file_yet": "No file yet. Choose one then click",
        "section_host_image_title": "Host an image for free",
        "section_host_image_p1": "PixShare is a service for hosting an image or a video for free and without registration. Files can be shared through a secure link and are automatically deleted after expiration.",
        "section_host_image_p2": "The service lets you in particular:",
        "feature_screenshot": "host a screenshot",
        "feature_share_image": "share an image quickly",
        "feature_temporary_file": "send a temporary file",
        "feature_short_video": "share a short video",
        "section_share_fast_title": "Share an image or file quickly",
        "section_share_fast_p1": "PixShare lets you upload an image, a screenshot or a short video and generate a secure sharing link. Files are automatically deleted after expiration to ensure privacy.",
        "section_share_fast_p2": "The service is designed to easily share:",
        "feature_image": "an image",
        "js_selected_prefix": "Selected: ",
        "js_leave_empty_original": "Leave empty to send the original image.",
        "js_sent_keeping_ratio": "Image sent in",
        "js_fill_width_or_height": "Enter a width or a height.",
        "js_image_resized_before_upload": "Image resized before upload to",
        "js_cannot_read_original_dimensions": "Unable to read the original image dimensions.",
        "js_invalid_dimensions": "Invalid dimensions for resizing.",
        "js_resizing_in_progress": "Resizing in progress...",
        "js_read_file_error": "Unable to read the file.",
        "js_load_image_resize_error": "Unable to load the image for resizing.",
        "contact": "Contact",
        "contact_report": "Report",
        "name_optional": "Name (optional)",
        "email_optional": "Email (optional)",
        "message": "Message",
        "message_description": "Describe your message or the problem you encountered...",
        "send": "Send",
        "shared_file_og_title": "File shared via PixShare",
        "report_pixshare_content": "Report PixShare content",
        "hosting": "Hosting",
        "illegal_content_report": "Illegal content report",
        "contact_form": "contact form",
        "legal_hosting_service": "PixShare is a temporary file hosting service that allows users to upload and share files through a secure link.",
        "legal_contact_help": "For any request, use the",
        "legal_intro_service": "PixShare is a temporary file hosting service.",
        "legal_temp_storage": "Files uploaded to PixShare are stored temporarily.",
        "legal_no_account": "PixShare does not require users to create an account.",
        "legal_not_permanent_storage": "The service is intended for quick file sharing and not for permanent storage.",
        "service_operation_retention": "Service operation and retention period",
        "retention_user_can_choose": "The user may choose a retention period when uploading.",
        "retention_max_limited": "The maximum duration is limited by the service in order to preserve the temporary nature of the hosting.",
        "retention_auto_delete": "Files are automatically deleted after expiration.",
        "retention_not_instant": "Deletion may not be instantaneous (a slight technical delay may occur).",
        "retention_availability_not_guaranteed": "Due to technical constraints (maintenance, server restart or hosting limitations), temporary file availability cannot be guaranteed.",
        "browser_resize_notice": "Some images may be resized in the browser before upload in order to optimize their size and display.",
        "personal_data": "Personal data",
        "security_ip_processing": "For security reasons and abuse prevention, certain technical data such as the IP address may be processed temporarily.",
        "data_used_only_for": "These data are used only to:",
        "prevent_service_abuse": "prevent abuse of the service",
        "block_access_malicious": "block access in the event of malicious behavior",
        "ensure_security_stability": "ensure the security and stability of the service",
        "temporary_browser_identifier": "A temporary technical identifier may also be stored in the browser in order to display the history of files uploaded from this browser. This identifier is not used for advertising tracking.",
        "no_profile_no_commercial_use": "No user profile is created and no commercial use of these data is made.",
        "responsibility": "Liability",
        "user_responsible_uploaded_files": "The user is responsible for the files they upload and for their compliance with applicable laws and regulations.",
        "legal_host_status": "PixShare acts as a technical hosting provider within the meaning of Article 6-I-2 of French Law No. 2004-575 of 21 June 2004 on confidence in the digital economy (LCEN).",
        "editor_not_responsible_user_content": "The publisher cannot be held responsible for content uploaded by users. However, any clearly illegal content may be removed without prior notice and access to the service may be blocked in case of abuse.",
        "legal_illegal_content_intro": "Anyone who believes that content hosted on PixShare is clearly illegal may report it to the service publisher.",
        "report_via_contact_form": "The report can be made through the",
        "report_message_must_contain": "The report must contain:",
        "report_required_url": "the URL address of the content concerned",
        "report_required_description": "a description of the disputed content",
        "report_required_reasons": "the reasons why the content is considered illegal",
        "report_required_contact_details": "the contact details of the person making the report",
        "legal_report_action": "After receiving a complete report, PixShare may proceed",
        "legal_report_action_suffix": "to remove the content concerned as quickly as possible.",
        "site_publisher": "Site publisher",
        "publisher_label": "Publisher",
        "site_version": "Site version",
        "editing": "Editor",
        "contat_info_use" : "Use this form to contact PixShare or report problematic content.",
        "contact_type_message": "Message type",
        
        
    },
}


def normalize_lang(lang: str | None) -> str:
    if not lang:
        return DEFAULT_LANG
    lang = lang.lower().strip()
    if lang.startswith("fr"):
        return "fr"
    if lang.startswith("en"):
        return "en"
    return DEFAULT_LANG



def apply_requested_language() -> None:
    requested = request.args.get("lang")
    if requested:
        lang = normalize_lang(requested)
        if lang in SUPPORTED_LANGS:
            session["lang"] = lang



def get_current_language() -> str:
    lang = session.get("lang")
    if lang in SUPPORTED_LANGS:
        return lang

    header = request.accept_languages.best_match(SUPPORTED_LANGS)
    return normalize_lang(header)



def translate(key: str) -> str:
    lang = get_current_language()

    if key not in TRANSLATIONS.get(lang, {}):
        print(f"[i18n missing] {key}")

    return TRANSLATIONS.get(lang, {}).get(
        key,
        TRANSLATIONS[DEFAULT_LANG].get(key, key)
    )



def build_lang_url(lang: str) -> str:
    lang = normalize_lang(lang)

    if not request.endpoint:
        return request.path

    values = dict(request.view_args or {})
    for k, v in request.args.items():
        if k != "lang":
            values[k] = v
    values["lang"] = lang

    try:
        return url_for(request.endpoint, **values)
    except Exception:
        return f"{request.path}?lang={lang}"
