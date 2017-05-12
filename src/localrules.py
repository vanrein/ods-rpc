# localrules.py -- Local actions on top of the genericapi.
#
# This is the local command extension interface -- it provides functions that
# return True on success and False on failure, when called with a zone name.
#
# The names of these functions are the same as the JSON command names.
# Keys and signatures are not handled here.  ACLs and states are also handled
# externally, as part of the genericapi.
#
# In addition, a few local settings are defined, such as:
#  * dig_ods is a "dig" command aimed at the OpenDNSSEC signer's output
#
# From: Rick van Rein <rick@openfortress.nl>


import os

import dns.resolver


#
# The name server that publishes OpenDNSSEC output (and makes it available to
# the/other public authoritatives).
#
ods_output = 'localhost'


#
# The local resolver is the default resolver for the entire Internet
#
local_resolver = dns.resolver.get_default_resolver ()


#
# A dig statement targeting a name server that is filled by the ods-signer output
#
digods = 'dig @localhost'


#
# The individual operations follow
#
# If you need to invoke a command as part of your callback, you can use
# the following body in the functions below:
#
#	# Demo implementation of calling a local script
#	cmdline = '/usr/local/surfdomeinen/bin/process_fetched ' + zone
#	retval = os.system ('sudo ' + cmdline)
#	return (retval == 0)
#
# If you need to test your infrastructure to handle failures reported
# by the local rules, you can use the following body in the functions below:
#
#	# Test implementation of uncertainty
#	from random import Random
#	rng = Random ()
#	return rng.uniform (0, 1) <= 0.3
#

def sign_start (zone):
	# No impact on the local implementation
	return True

def sign_approve (zone):
	# No impact on the local implementation
	return True

def assert_signed (zone):
	# No impact on the local implementation
	return True

def chain_start (zone):
	# No impact on the local implementation
	return True

def assert_chained (zone):
	# No impact on the local implementation
	return True

def chain_stop (zone):
	# No impact on the local implementation
	return True

def assert_unchained (zone):
	# No impact on the local implementation
	return True

def sign_ignore (zone):
	# No impact on the local implementation
	return True

def sign_stop (zone):
	# No impact on the local implementation
	return True

def assert_unsigned (zone):
	# No impact on the local implementation
	return True

def update_signed (zone):
	# No impact on the local implementation
	return True

