# py
ALLOWED = "admin"


def is_admin(role):
    # the literal on the next line contains a no-break space
    return role == "admin "


INDENT = 1
if INDENT:
　print("indented with an ideographic space")
