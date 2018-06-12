
from os.path import dirname, abspath, join

_dirpath = dirname(abspath(__file__))
PASSWORD_FILEPATH = join(_dirpath, 'passwords.encrypted')
RSAKEY_FILEPATH = join(_dirpath, 'rsa.key')
