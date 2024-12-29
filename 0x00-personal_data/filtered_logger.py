#!/usr/bin/env python3
""" Logging """


import re
import os
from unittest import result
from webbrowser import get
import mysql.connector
import logging
from typing import List

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')
""" tuple that contains five most relevant data """


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str
                 ) -> str:
    """ Return log message """
    for field in fields:
        message = re.sub(fr'{field}=.+?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ constractor """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ filter values in incoming log records """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """ Return logging.Logger object """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ returns a connector """
    return mysql.connector.connect(
        host=os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.environ.get('PERSONAL_DATA_DB_NAME', 'root'),
        user=os.environ.get('PERSONAL_DATA_DB_USERNAME'),
        password=os.environ.get('PERSONAL_DATA_DB_PASSWORD', ''))


# def main() -> None:
#     """ Main method """
#     conn = get_db()
#     cursor = conn.cursor()
#     query = "SELECT * FROM users;"
#     cursor.execute(query)
#     result = cursor.fetchall()
#     for row in result:
#         message = f"name={row[0]}; " + \
#                   f"email={row[1]}; " + \
#                   f"phone={row[2]}; " + \
#                   f"ssn={row[3]}; " + \
#                   f"password={row[4]};"
#         print(message)

#     log_record = logging.LogRecord("my_logger", logging.INFO,
#                                    None, None, message, None, None)
#     formatter = RedactingFormatter(PII_FIELDS)
#     formatter.format(log_record)
#     cursor.close()
#     conn.close()


if __name__ == "__main__":
    main()
