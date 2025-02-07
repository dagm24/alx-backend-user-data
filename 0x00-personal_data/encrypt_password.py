#!/usr/bin/env python3
""" Encryption """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashed password """
    password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Check valid password """
    password = password.encode('utf-8')
    if bcrypt.checkpw(password, hashed_password):
        return True
    else:
        return False
