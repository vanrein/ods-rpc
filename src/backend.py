# backend.py -- Adding and removing zones with the backend of choice.
#
# This is where you switch between backends for managing and unmanaging zones.
# The two backends currently supported are:
#  - adding and removing zones with the Enforcer
#  - direct generation of keys over PKCS #11 and generation of zones.xml
#
# From: Rick van Rein <rick@openfortress.nl>


from backksm import *
# from backdirect import *

