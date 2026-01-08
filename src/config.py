import logging
import datetime
import sys

# Parse API key từ command line -k (nếu có)
_temp_key = "NOT NEEDED"
if '-k' in sys.argv:
    try:
        k_index = sys.argv.index('-k')
        if k_index + 1 < len(sys.argv):
            _temp_key = sys.argv[k_index + 1]
    except:
        pass

OPENAI_API_KEY = _temp_key

OPENAI_APIS = [_temp_key]

GPT4_API = _temp_key

GITHUB_TOKEN = "NOT NEEDED"
LOGGING_LEVEL = logging.INFO
LOGGING_FORMAT = "%(name)s: %(message)s"
# LOGGING_TARGET = datetime.datetime.now().strftime("logs/main.py-output-%Y%m%d-%H%M%S.log")
STATEMENT_FILE = "output/statements.csv"
WRITE_STATEMENTS_INTO_FILE = True
BACKUP_STATEMENTS = True

ENABLE_STATIC_ANALYSIS = True

SEND_PRICE = 0.0015 / 1000
RECEIVE_PRICE = 0.002 / 1000

GPT4_SEND_PRICE = 0.03 / 1000
GPT4_RECEIVE_PRICE = 0.06 / 1000