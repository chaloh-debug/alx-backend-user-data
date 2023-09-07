#!/usr/bin/env python3
"""Session authentication module.
"""
from uuid import uuid4
from .auth import Auth


class SessionAuth(Auth):
    """Session authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates a Session ID.
        """
        if isinstance(user_id, str):
            if user_id is not None:
                session_id = str(uuid4())
                self.user_id_by_session_id[session_id] = user_id
                return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns a User ID based on a Session ID.
        """
        if isinstance(session_id, str):
            if session_id is not None:
                return self.user_id_by_session_id.get(session_id)
        return None

    def current_user(self, request=None):
        """Returns a User instance based on a cookie value.
        """
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Deletes the user session / logout.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if (request is None or session_id is None) or user_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
