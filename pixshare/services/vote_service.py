import hashlib
import json
import os
from copy import deepcopy

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
VOTES_PATH = os.path.join(DATA_DIR, "votes.json")

IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".avif"
}


def ensure_votes_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(VOTES_PATH):
        with open(VOTES_PATH, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)


def load_votes():
    ensure_votes_file()
    try:
        with open(VOTES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_votes(data):
    ensure_votes_file()
    tmp_path = VOTES_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, VOTES_PATH)


def hash_ip(client_ip):
    client_ip = (client_ip or "").strip()
    if not client_ip:
        return ""
    return hashlib.sha256(client_ip.encode("utf-8")).hexdigest()


def is_image_filename(filename):
    if not filename:
        return False
    name = str(filename).lower()
    return any(name.endswith(ext) for ext in IMAGE_EXTENSIONS)


def _normalize_vote(v):
    v = (v or "").strip().lower()
    return v if v in {"up", "down"} else None


def _get_entry(votes, file_id):
    entry = votes.get(file_id)
    if not isinstance(entry, dict):
        entry = {"votes": {}}
    if "votes" not in entry or not isinstance(entry["votes"], dict):
        entry["votes"] = {}
    return entry


def get_vote_summary(file_id, client_ip=None):
    votes = load_votes()
    entry = _get_entry(votes, file_id)
    file_votes = entry.get("votes", {})

    up = 0
    down = 0
    for value in file_votes.values():
        norm = _normalize_vote(value)
        if norm == "up":
            up += 1
        elif norm == "down":
            down += 1

    current_vote = None
    ip_hash = hash_ip(client_ip)
    if ip_hash:
        current_vote = _normalize_vote(file_votes.get(ip_hash))

    return {
        "up": up,
        "down": down,
        "score": up - down,
        "total": up + down,
        "current_vote": current_vote,
    }


def register_vote(file_id, client_ip, vote_value):
    vote_value = _normalize_vote(vote_value)
    if vote_value is None:
        raise ValueError("vote_value must be 'up' or 'down'")

    ip_hash = hash_ip(client_ip)
    if not ip_hash:
        raise ValueError("client_ip is required")

    votes = load_votes()
    entry = _get_entry(votes, file_id)
    entry["votes"][ip_hash] = vote_value
    votes[file_id] = entry
    save_votes(votes)

    return get_vote_summary(file_id, client_ip)


def delete_votes_for_file(file_id):
    votes = load_votes()
    if file_id in votes:
        del votes[file_id]
        save_votes(votes)


def cleanup_votes_for_existing_file_ids(existing_file_ids):
    existing = set(existing_file_ids or [])
    votes = load_votes()
    original = deepcopy(votes)

    for file_id in list(votes.keys()):
        if file_id not in existing:
            del votes[file_id]

    if votes != original:
        save_votes(votes)