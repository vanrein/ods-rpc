#!/usr/bin/env python
#
# Verify and decode a JOSE request.
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
# The received information, to be extracted and processed
#
received = """
{
   "header": "eyJ0aW1lc3RhbXAiOiAxNDIzMDQ0OTY3LjczNDk1MiwgImFsZyI6ICJIUzI1NiIsICJjdHkiOiAiYXBwbGljYXRpb24vanNvbiIsICJraWQiOiAicG9ydGFsK2tleTFAZGV2ZWwuc3VyZmRvbWVpbmVuLm5sIn0", 
   "payload": "eyJ6b25lcyI6IFsidmFucmVpbi5vcmciLCAib3BlbmZvcnRyZXNzLm5sIiwgInN1cmZuZXQubmwiXSwgImNtZCI6ICJzaWduX3N0YXJ0In0", 
   "signature": "5xSVfItNIGQLZVMtM-W-hhHbI_ke8DxDj34NZt7oXQs"
}
"""

# ALT, TEST:
receieved = """
{
"header": "eyJ0aW1lc3RhbXAiOiAxNDI0NzY2MzgzLjM2NzQxNzEsICJhbGciOiAiSFMyNTYiLCAiY3R5IjogImFwcGxpY2F0aW9uL2pzb24iLCAia2lkIjogInBvcnRhbCtrZXkxQGV4YW1wbGUuY29tIn0
",
"payload": "eyJ6b25lcyI6IFsidmFucmVpbi5vcmciXSwgImNvbW1hbmQiOiAic2lnbl9zdGFydCJ9",
"signature": "AA70gI7BXgoFkZ1QN8L4PFmfleyQDA0xma0t_zyN5Cg"
}
"""

# ALT, TEST2:
received = """
{
"header": "eyJ0aW1lc3RhbXAiOiAxNDI0Nzc0MzQ0LjE5NTQ0OTEsICJhbGciOiAiSFMyNTYiLCAiY3R5IjogImFwcGxpY2F0aW9uL2pzb24iLCAia2lkIjogInBvcnRhbCtrZXkxQGV4YW1wbGUuY29tIn0",
"payload": "eyJ6b25lcyI6IFsidmFucmVpbi5vcmciXSwgImNvbW1hbmQiOiAic2lnbl9zdGFydCJ9",
"signature": "GCZ4sViPSjfqb0c4rdOty9RmAVo-9-d95Ztl5k84qf0"
}
"""

#
# Extract base64 information
#
def extractdata (b64ish):
	for padding in ['', '=', '==', '===', '====', '=====']:
		try:
			xdata = json.loads ((b64ish + padding).decode ('base64'))
			return xdata
		except:
			pass	# padding error
	return None

#
# Retrieve description in the signed data
#
signeddata = json.loads (received)
jws = jose.JWS (signeddata ['header'], signeddata ['payload'], signeddata ['signature'])
print 'JWS =', jws
# print '_asdict is', jose.JWS (signeddata)._asdict ()
hdr = extractdata (signeddata ['header'])
print hdr, '::', type (hdr)
for k in hdr.keys ():
	print k, 'is set to', hdr [k]
print 'Signature age is', time.time () - hdr ['timestamp'], 'seconds'

#
# Validate the signature
#
try:
	# jose.verify (signeddata, sharedkey)
	jose.verify (jws, sharedkey)
	print 'Signature correct'
except Exception, e:
	print 'SIGNATURE BAD:', e

