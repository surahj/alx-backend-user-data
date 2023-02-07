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
