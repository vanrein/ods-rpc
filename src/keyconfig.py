# keyconfig.py -- Signing keys for accessing ods-webapi
#
# All keys should include a key-identifier (kid) to simplify changes to users,
# their keys and their acceptable domains.
#
# All keys should include their signing mechanism, so ods-webapi can stay
# agnostic to this choice.  The ods-webapi will differentiate only between
# keys for signing and verification, which are trivially the same for
# symmetric algorithms.
#
# A usable symmetric algorithm is HMAC-SHA256, called 'HS256' in JWS.
#
# From: Rick van Rein <rick@openfortress.nl>


keys = { }

def newkey (k):
	keys [k ['kid']] = k

#
# The shared key contains a secret and the related algorithm information
#
newkey ( {
        'kid': 'portal+key1@example.com',
        'kty': 'oct',
        'alg': 'HS256',
        'k': '3jW0FJjW6noL2Ue0sMpAh1O1VD5qB3yUiE7T83AfPUg',
} )


