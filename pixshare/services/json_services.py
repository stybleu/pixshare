from flask import current_app
from pixshare.storage import (
    atomic_write_json,
    blocked_path,
    contacts_path,
    db_path,
    failed_logins_path,
    read_json_file,
    views_path,
    votes_path,
)


def load_db() -> dict:
    return read_json_file(db_path(current_app), {})


def save_db(db: dict) -> None:
    atomic_write_json(db_path(current_app), db)


def load_blocked() -> list:
    return read_json_file(blocked_path(current_app), [])


def save_blocked(blocked: list) -> None:
    atomic_write_json(blocked_path(current_app), blocked)


def load_views() -> dict:
    return read_json_file(views_path(current_app), {})


def save_views(data: dict) -> None:
    atomic_write_json(views_path(current_app), data)


def load_contacts() -> list:
    return read_json_file(contacts_path(current_app), [])


def save_contacts(items: list) -> None:
    atomic_write_json(contacts_path(current_app), items)


def load_failed_logins() -> dict:
    return read_json_file(failed_logins_path(current_app), {})


def save_failed_logins(data: dict) -> None:
    atomic_write_json(failed_logins_path(current_app), data)


def load_votes() -> dict:
    return read_json_file(votes_path(current_app), {})


def save_votes(data: dict) -> None:
    atomic_write_json(votes_path(current_app), data)
