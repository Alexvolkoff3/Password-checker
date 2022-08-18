import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check api and try again')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):  # check password if it exists in api response
    sha1password = hashlib.sha1(password.encode(
        'utf-8')).hexdigest().upper()  # must be encoded before hashing then convert to hexdecimal string
    first5_char, tail = sha1password[0:5], sha1password[5:]
    resp = request_api_data(first5_char)
    return get_password_leaks_count(resp, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times... You should change your password")
        else:
            print(f"{password} was not found. Good password.")
    return 'done'


main(sys.argv[1:])
