# py
def check_pаssword(value):
    return value == "expected"


def login(user, value):
    # calls the Cyrillic spelling above, not check_password
    return check_pаssword(value)
