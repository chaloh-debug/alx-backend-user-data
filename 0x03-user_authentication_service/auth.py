#!/usr/bin/env python3
"""User authentication  module.
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Returns a hashed password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate uuid.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers new users.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Verify user details.
        """
        usr = None
        try:
            usr = self._db.find_user_by(email=email)
            if usr is not None:
                return bcrypt.checkpw(password.encode("utf-8"),
                                      usr.hashed_password)
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Create a session ID.
        """
        usr = None
        try:
            usr = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if usr is None:
            return None
        sess_id = _generate_uuid()
        self._db.update_user(usr.id, session_id=sess_id)

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieve user based on session ID.
        """
        usr = None
        if session_id is None:
            return None
        try:
            usr = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return usr

    def destroy_session(self, user_id: str) -> None:
        """Destroy a user session.
        """
        if user_id is not None:
            self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generate reset password token.
        """
        usr = None
        try:
            usr = self._db.find_user_by(email=email)
        except NoResultFound:
            usr = None
        if usr is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(usr.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates password given a reset token.
        """
        usr = None
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            usr = None
        if usr is None:
            raise ValueError()
        new_pass = _hash_password(password)
        self._db.update_user(usr.id, hashed_password=new_pass,
                             reset_token=None)
