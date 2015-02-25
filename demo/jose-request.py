#!/usr/bin/env python
#
# portal-jose-request.py -- Demonstration JOSE requests as the Portal sends
#
# From: Rick van Rein <rick@openfortress.nl>


import time

import json
import jose


#
# The shared key contains a secret and the related algorithm information
#
sharedkey = {
	'kid': 'portal+key1@devel.surfdomeinen.nl',
	'kty': 'oct',
	'alg': 'HS256',
	'k': '3jW0FJjW6noL2Ue0sMpAh1O1VD5qB3yUiE7T83AfPUg',
}

#
# The request signifies a command, plus a list of zones to which it is applied
#
request = {
	'cmd': 'sign_start',
	'zones': [
		'vanrein.org',
		'openfortress.nl',
		'surfnet.nl',
	],
}

#
# The request header reveals information about the signature
#
reqhdr = {
	'cty': 'application/json',
	'kid': 'portal+key1@surfdomeinen.nl',
	'timestamp': time.time (),
}

#
# Following demonstration code signs, maps to a dictionary and maps that to JSON
#
reqhdr ['kid'] = sharedkey ['kid']
tobesent = jose.sign (request, sharedkey, add_header = reqhdr)
tobesent = tobesent._asdict ()
tobesent = json.dumps (tobesent, indent=3)
#
# End of demonstration code
#

print '-----BEGIN TO BE SENT-----'
print 'Content-type: application/jws+json'
print
print tobesent
print '-----END TO BE SENT-----'

