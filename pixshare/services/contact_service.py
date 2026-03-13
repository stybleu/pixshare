import secrets
from .json_services import load_contacts, save_contacts
from .request_service import get_client_ip
from .time_service import utcnow


def create_contact_message(msg_type: str, name: str, email: str, subject: str, message: str, file_url: str) -> None:
    contacts = load_contacts()
    contacts.append({
        "id": secrets.token_urlsafe(8),
        "created_at": utcnow().isoformat(timespec="seconds"),
        "type": msg_type,
        "name": name,
        "email": email,
        "subject": subject,
        "message": message,
        "file_url": file_url,
        "ip": get_client_ip(),
        "status": "new",
    })
    save_contacts(contacts)
