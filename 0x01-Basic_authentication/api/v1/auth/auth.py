#!/usr/bin/env python3
"""
Contains Auth class which is the base class for
all authentication methods
"""
from typing import List
from typing import TypeVar


class Auth:
    """
    Base class for authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Finds for the path in the excluded_paths list.
        Args:
            path: The path to check.
            excluded_paths: The list of paths to exclude.
        Returns:
            True if the path is not in the excluded_paths list.
            True if path is None or excluded_paths is None or empty.
            False otherwise.
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
        if path not in excluded_paths:
            return True

        return False

    def authorization_header(self, request=None) -> str:
        """
        Determines if a request has valid authorization headers.
        Args:
            request: The request to check.
        Returns:
            The authorization header if it exists.
            None otherwise.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Return current_user
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves user depending on the credentials provided
        from request
        Args:
            request: flask request object
        """
        header = self.authorization_header(request)
        base64_authorization_header = \
            self.extract_base64_authorization_header(header)
        decoded_base64_authorization_header = \
            self.decode_base64_authorization_header(
                base64_authorization_header)
        user_email, user_pwd = self.extract_user_credentials(
            decoded_base64_authorization_header)
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
