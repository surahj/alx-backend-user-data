#!/usr/bin/env python3
"""
Contains class SessionAuth that handles
session authentication.
"""
from api.v1.auth.auth import Auth
import uuid
from models.user import User


class SessionAuth(Auth):
    """
    Handles session authentication.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session.
        Args:
            user_id: The user id.
        Returns:
            The session id.
        """
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

