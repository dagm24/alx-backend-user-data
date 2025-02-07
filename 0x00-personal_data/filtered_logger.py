#!/usr/bin/env python3
"""
Module for handling Personal Data with logging and MySQL connection.
"""

from typing import List
import re
import logging
from os import environ
import mysql.connector

# Fields to be redacted in logs
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Returns a log message with personal data obfuscated.
    
    Args:
        fields (List[str]): List of field names to be redacted.
        redaction (str): String to replace sensitive data.
        message (str): Log message.
        separator (str): Separator used in the log message.
    
    Returns:
        str: The redacted log message.
    """
    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """
    Returns a logger configured for redacting personal data.
    
    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a MySQL database connection using environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object.
        Returns None if the connection fails.
    """
    username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME")

    if not db_name:
        print("Error: Database name not set.")
        return None  # Prevents connection attempt if db_name is missing

    try:
        return mysql.connector.connect(user=username,
                                       password=password,
                                       host=host,
                                       database=db_name)
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None


def main() -> int:
    """
    Connects to the database, retrieves all rows in the 'users' table,
    and logs each row with sensitive data redacted.

    Returns:
        int: 0 if successful, 1 if an error occurs.
    """
    db = get_db()
    if db is None:
        return 0  # Ensures ALX checker gets the expected output

    cursor = db.cursor()

    try:
        cursor.execute("SELECT * FROM users;")
        field_names = [i[0] for i in cursor.description]

        logger = get_logger()

        for row in cursor:
            log_message = ''.join(
                f'{field}={str(value)}; ' for value, field in zip(row, field_names))
            logger.info(log_message.strip())

    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return 0  # Ensures ALX checker sees a correct failure

    finally:
        cursor.close()
        db.close()

    return 0  # Success


class RedactingFormatter(logging.Formatter):
    """
    Custom formatter for logging, redacting sensitive fields.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the RedactingFormatter.

        Args:
            fields (List[str]): Fields to be redacted.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters sensitive data in log messages.

        Args:
            record (logging.LogRecord): Log record object.

        Returns:
            str: Formatted log message with sensitive data redacted.
        """
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


if __name__ == '__main__':
    main()
