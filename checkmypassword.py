import requests  # package to request data
import hashlib   # package to hash the password
#import sys       # to parse arguments
from getpass import getpass   # to parse the password

def request_api_data(query_char):
    """
    :param query_char: str, 5 length string with query characters
    :return: response object from requests.get
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(password):
    count = pwned_api_check(password)
    if count:
        print('*'*len(password), f'was found {count} times... you should probably change your password!')
    else:
        print('*'*len(password), 'was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    main(getpass())
