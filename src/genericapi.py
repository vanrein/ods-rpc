# genericapi.py -- The command interface for the OpenDNSSEC API
#
# This is a general command interface -- it processes a JSON-formatted
# DNSSEC Request and produces a JSON-formatted DNSSEC Request.  Keys and
# signatures are not handled here, with the exception of the key identity
# on the DNSSEC Request, which is used to control access to the requested
# command.  The API is generic in the sense that it only cares for the
# JSON-content, much less about whether the transport is HTTP, CoAP, SMTP
# or anything else you might dream up.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import re
import os
import os.path
import syslog
import time

from commandaccess import acls
import localrules
import dnslogic


# The directory under which the flags are made
flagdir = '/var/opendnssec/rpc'

if not os.path.isdir (flagdir):
	syslog.syslog (syslog.LOG_ERR, 'Missing control directory: ' + flagdir + ' (FATAL)')
	sys.exit (1)

# The flagging system; zone name plus flag name; file absense is False
def flagged (zone, flagname, value=None):
	error = False
	flagfile = flagdir + os.sep + zone + os.extsep + flagname
	if value is not None:
		if value is not False:
			try:
				fh = open (flagfile, 'w')
				if value is True:
					valstr = ''
				else:
					valstr = str (value) + '\n'
				fh.write (valstr)
				fh.close ()
			except:
				# Check below
				pass
		else:
			try:
				os.unlink (flagfile)
			except:
				# Check below
				pass
	try:
		fh = open (flagfile, 'r')
		retval = fh.read ()
		fh.close ()
		if retval [-1:] == '\n':
			retval = retval [:-1]
		if retval == '':
			retval = True
	except:
		retval = False
	if value is not None and retval != value:
		print 'FLAG', flagname, 'IS', retval, '::', type (retval), 'AND SHOULD BE', value, '::', type (value)
		# It is abnormal for this to happen
		syslog.syslog (syslog.LOG_ERR, 'Failed to set ' + flagname + ' flag to ' + str (value))
		if not flagged (zone, 'invalid', value='Failed to set ' + flagname + ' flag to ' + str (value)):
			syslog.syslog (syslog.LOG_ERR, 'In addition, failed to set error flag to True (FATAL)')
			sys.exit (1)
	print 'RETURNING', retval, 'FOR', flagname
	return retval

def flagged_signing (zone, value=None):
	return flagged (zone, 'signing', value)

def flagged_signed (zone, value=None):
	return flagged (zone, 'signed', value)

def flagged_chaining (zone, value=None):
	return flagged (zone, 'chaining', value)

def flagged_chained (zone, value=None):
	return flagged (zone, 'chained', value)

def flagged_unchaining (zone, value=None):
	return flagged (zone, 'unchaining', value)

def flagged_unsigning (zone, value=None):
	return flagged (zone, 'unsigning', value)

def flagged_invalid (zone, value=None):
	return flagged (zone, 'invalid', value)

def flagged_dnskeyttl (zone, value=None):
	return flagged (zone, 'dnskeyttl', value)

def flagged_dsttl (zone, value=None):
	return flagged (zone, 'dsttl', value)


# Symbolic names for result lists of zones
RES_OK       = 'ok'
RES_ERROR    = 'error'
RES_INVALID  = 'invalid'
RES_BADSTATE = 'badstate'


# The syntax pattern for DNS zone names.
# The syntax is based on RFC 1035 section 2.3.1
# It adds the commonly permitted digits at the start of a label.
# The name is assumed to first be mapped to lowercase.
#
# Note that hyphens are permitted only between letters/digits.
# Note that there must be at least two labels.
# Note that a trailing dot is not permitted.
dnsre = re.compile ('^[0-9a-z]+(-[0-9a-z]+)*(\.[0-9a-z]+(-[0-9a-z])*)+$')


#
# The individual operations follow, with do_ prefixed to the command name
#

def do_sign_start (zone, kid):
	if flagged_signing (zone) or flagged_chaining (zone):
		return RES_BADSTATE
	# No local checks or actions to start signing
	if localrules.sign_start (zone):
		return RES_OK
	else:
		return RES_ERROR

def do_sign_approve (zone, kid):
	if flagged_signing (zone) or flagged_chaining (zone):
		return RES_BADSTATE
	# Assertion that there is no 'signed' flag yet
	if flagged_signed (zone):
		flagged_invalid (zone, value='During sign_approve() of ' + zone + ' the signed flag was already set')
		return RES_INVALID
	if not localrules.sign_approve (zone):
		return RES_ERROR
	#TODO# Make less local -- where the input files come from
	cmd = 'ods-ksmutil zone add --zone "' + zone + '" -i "/var/opendnssec/unsigned/' + zone + '.axfr" -o "/var/named/chroot/var/named/opendnssec/' + zone + '" -p SURFdomeinen'
	if os.system (cmd) != 0:
		syslog.syslog (syslog.LOG_ERR, 'Failed to add zone ' + zone + ' to OpenDNSSEC')
		return RES_ERROR
	if flagged_signing (zone, value=True):
		return RES_OK
	else:
		return RES_ERROR

def do_assert_signed (zone, kid):
	# Precondition testing
	if (not flagged_signing (zone)) or flagged_chaining (zone):
		return RES_BADSTATE
	#
	# Give the local rule logic first chance
	if not localrules.assert_signed (zone):
		return RES_ERROR
	#
	# Find if we already set the 'signed' flag to a desired endtime
	try:
		asserted_fromtm = int (flagged_signed (zone) or 'NOTANINT')
		print 'LOADED ASSERTED-FROM TIME', asserted_fromtm
	except:
		# flagged_invalid (zone, value='Flag signed failed to load as an integer')
		# return RES_INVALID
		asserted_fromtm = None
		print 'NO ASSERTED-FROM TIME IS signed FLAG YET'
	#
	# Consider the case that no signatures may have been found before;
	# this will check DNS and store a now-plus-TTL in the 'signed' flag
	if asserted_fromtm is None:
		if dnslogic.test_for_signed_dnskey (
				zone,
				dnslogic.PUBLISHER_AUTHORITATIVES |
				dnslogic.PUBLISHER_ALL):
			ass1ttl = dnslogic.dnskey_ttl (
					zone,
					dnslogic.PUBLISHER_OPENDNSSEC)
			ass2ttl = dnslogic.negative_caching_ttl (
					zone,
					dnslogic.PUBLISHER_OPENDNSSEC)
			asserted_fromtm = dnslogic.ttl2endtime (
					max (ass1ttl, ass2ttl))
			print 'COMPUTED ASSERTED-FROM TIME TO BE', asserted_fromtm, 'BASED ON', ass1ttl, 'AND', ass2ttl
			if asserted_fromtm is not None:
				flagged_signed (zone, value=str (asserted_fromtm))
			else:
				syslog.syslog (syslog.LOG_ERR, 'Failed to determine endtime in OpenDNSSEC during assert_signed on ' + zone)
				return RES_ERROR
		else:
			print 'STILL FOUND NO DNSKEY RECORDS'
			syslog.syslog (syslog.LOG_INFO, 'Failed to assert that zone ' + zone + ' is published-signed')
			return RES_ERROR
	#
	# Now test the asserted_fromtm value
	if time.time () >= asserted_fromtm:
		print 'ENDED COUNTDOWN UNTIL', asserted_fromtm
		return RES_OK
	else:
		print 'STILL DOING COUNTDOWN UNTIL', asserted_fromtm
		return RES_ERROR

def do_chain_start (zone, kid):
	# Pre-condition is that assert_signed returns RES_OK
	assn = do_assert_signed (zone, kid)
	if assn != RES_OK:
		return assn
	# Assertion that there is no 'chained' flag yet...
	if flagged_chained (zone):
		flagged_invalid (zone, value='The chained flag was already set during chain_start()')
		return RES_INVALID
	# ...and that there are no DS records yet...
	if dnslogic.have_ds (zone):
		flagged_invalid (zone, value='DS TTL already found in parent')
	# ... then, continue into the actions for starting the chain
	if localrules.chain_start (zone):
		if flagged_chaining (zone, value=True):
			return RES_OK
		else:
			syslog.syslog (syslog.LOG_ERR, 'Failed to set chaining flag on zone ' + zone)
			return RES_INVALID
	else:
		return RES_ERROR

def do_assert_chained (zone, kid):
	#
	# First check preconditions
	if (not flagged_signed (zone)) or (not flagged_chaining (zone)):
		return RES_BADSTATE
	#
	# Find if we already set the 'chained' flag to a desired endtime
	try:
		asserted_fromtm = int (flagged_chained (zone) or 'NOTANINT')
		print 'LOADED CHAINED ASSERTED-FROM TIME', asserted_fromtm
	except:
		# flagged_invalid (zone, value='Flag chained failed to load as an integer')
		print 'NO CHAINED ASSERTED-FROM TIME YET'
		asserted_fromtm = None
	#
	# The DS records may be absent, which is a sign that we need to
	# back off and retry later; this can happen when another process
	# handles the submission of DS with delays
	if not dnslogic.have_ds (zone):
		return RES_ERROR
	#
	# Consider the case that no chaining records may have been found yet;
	# this will check DNS and store a now-plus-TTL in the 'signed' flag
	if asserted_fromtm is None:
		if localrules.assert_chained (zone):
			ass1tm = dnslogic.ds_ttl (
					zone,
					dnslogic.PUBLISHER_PARENTS)
			ass2tm = dnslogic.negative_caching_ttl (
					zone,
					dnslogic.PUBLISHER_PARENTS)
			asserted_fromtm = dnslogic.ttl2endtime (
					max (ass1tm, ass2tm))
			print 'COMPUTED CHAINED ASSERTED-FROM TIME', asserted_fromtm, 'FROM', ass1tm, 'AND', ass2tm
			if asserted_fromtm is not None:
				flagged_chained (zone, value=str (asserted_fromtm))
			else:
				return RES_ERROR
		else:
			return RES_ERROR
	#
	# Now test the asserted_fromtm value
	if time.time () >= asserted_fromtm:
		print 'PASSED ACROSS THE CHAINED ASSERTED-FROM TIME', asserted_fromtm
		return RES_OK
	else:
		print 'COUNTING DOWN TO THE CHAINED ASSERTED-FROM TIME', asserted_fromtm
		return RES_ERROR

def do_chain_stop (zone, kid):
	if (not flagged_signed (zone)) or (not flagged_chained (zone)):
		return RES_BADSTATE
	# Permit only one chain_stop call:
	if not flagged_chaining (zone):
		return RES_BADSTATE
	# Compute the new
	dsttl = dnslogic.ds_ttl (zone)
	if dsttl is None:
		flagged_invalid (zone, value='No DS TTL found in parent')
	flagged_dsttl (zone, value=str (dsttl))
	if localrules.chain_stop (zone):
		if (not flagged_chaining (zone, value=False)) and (not flagged_chained (zone, value=False)):
			return RES_OK
		else:
			syslog.syslog (syslog.LOG_ERR, 'Failed to clear chained/chaining flags on zone ' + zone)
			return RES_INVALID
	else:
		syslog.syslog (syslog.LOG_ERR, 'Failed in localrules.chain_stop() on zone ' + zone)
		return RES_ERROR

def do_assert_unchained (zone, kid):
	if (not flagged_signed (zone)) or flagged_chaining (zone) or flagged_chained (zone):
		return RES_BADSTATE
	try:
		dsttl = flagged_dsttl (zone)
	except:
		# flagged_dsttl did not get set by chain_stop() as expected
		return RES_BADSTATE
	if dnslogic.have_ds (zone):
		# We're still waiting for the parent DS to disappear
		return RES_ERROR
	if not localrules.assert_unchained (zone):
		# Something local is stopping us from asserting unchained status
		return RES_ERROR
	#
	# We now start the count down for the DS TTL or, if it has started
	# already, we check the clock time to see if it expired already.
	#
	try:
		dsttlend = int (flagged_unchaining (zone))
	except:
		dsttlend = dnslogic.ttl2endtime (dsttl)
		flagged_unchaining (zone, value=dsttlend)
	if time.time () < dsttlend:
		# We need to wait somewhat longer
		return RES_ERROR
	else:
		# The flagged_unchaining time has passed
		return RES_OK

def do_sign_ignore (zone, kid):
	if (not flagged_signed (zone)) or flagged_chained (zone):
		return RES_BADSTATE
	if localrules.sign_ignore (zone):
		# Name servers reconfigured to no longer serve the zone
		return RES_OK
	else:
		return RES_ERROR

def do_sign_stop (zone, kid):
	if (not flagged_signed (zone)) or flagged_chained (zone):
		print 'FLAGS ARE OFF -- BADSTATE'
		return RES_BADSTATE
	dnskeyttl = dnslogic.dnskey_ttl (
				zone,
				dnslogic.PUBLISHER_OPENDNSSEC)
	if flagged_dnskeyttl (zone, value=str (dnskeyttl)) != str (dnskeyttl):
		return RES_INVALID
	if not localrules.sign_stop (zone):
		return RES_ERROR
	cmd = 'ods-ksmutil zone delete --zone "' + zone + '"'
	if os.system (cmd) != 0:
		syslog.syslog (syslog.LOG_ERR, 'Failed to remove zone ' + zone + ' from OpenDNSSEC')
		return RES_ERROR
	# Retract the basis of certainty for assert_signed()
	if not flagged_signed (zone, value=False):
		return RES_OK
	else:
		return RES_ERROR

def do_assert_unsigned (zone, kid):
	# Test preconditions
	if flagged_signed (zone) or flagged_chained (zone):
		return RES_BADSTATE
	# After first RES_OK returned, absense of flagged_signing suffices
	if not flagged_signing (zone):
		return RES_OK
	# Not completely done, so pickup some information
	try:
		dnskeyttl = int (flagged_dnskeyttl (zone))
	except:
		# The DNSKEY TTL was not saved by sign_stop() as expected
		return RES_BADSTATE
	unsigning = flagged_unsigning (zone)
	if unsigning is None and not dnslogic.test_for_signed_dnskey (
			zone,
			dnslogic.PUBLISHER_AUTHORITATIVES |
			dnslogic.PUBLISHER_NONE):
		syslog.syslog (syslog.LOG_INFO, 'Failed to assert that zone ' + zone + ' is published-unsigned')
		return RES_ERROR
	if not localrules.assert_unsigned (zone):
		return RES_ERROR
	#
	# The countdown for DNSKEY TTL only starts now, after localrules have
	# returned True once.  This may be used to investigate various local
	# aspects before assuming that the DNSKEY may disappear.
	#
	if unsigning is False:
		# The countdown has not started yet, so start it now
		dnskeyttlend = dnslogic.ttl2endtime (dnskeyttl)
		print 'CREATED TTLEND FOR DNSKEY:', dnskeyttlend
		flagged_unsigning (zone, value=str (dnskeyttlend))
	else:
		dnskeyttlend = int (unsigning)
		print 'GOT TTLEND FOR DNSKEY:', dnskeyttlend
	if time.time () < dnskeyttlend:
		# The countdown has not yet completed, so tick a little more
		print 'AWAITING COUNTDOWN UNTIL:', dnskeyttlend
		return RES_ERROR
	else:
		# The countdown is complete, so cleanup flags and report success
		print 'COMPLETED COUNTDOWN UNTIL:', dnskeyttlend
		if flagged_signing (zone, value=False):
			return RES_INVALID
		flagged_dsttl (zone, value=False)
		flagged_dnskeyttl (zone, value=False)
		flagged_unsigning (zone, value=False)
		return RES_OK


#
# Map command names to the procedures that apply them to individual zones
#
handler = { }
handler ['sign_start'      ] = do_sign_start
handler ['sign_approve'    ] = do_sign_approve
handler ['assert_signed'   ] = do_assert_signed
handler ['chain_start'     ] = do_chain_start
handler ['assert_chained'  ] = do_assert_chained
handler ['chain_stop'      ] = do_chain_stop
handler ['assert_unchained'] = do_assert_unchained
handler ['sign_ignore'     ] = do_sign_ignore
handler ['sign_stop'       ] = do_sign_stop
handler ['assert_unsigned' ] = do_assert_unsigned


#
# The general access point to running the command for a given key identity.
# The key identity is assumed to have been verified by the caller through JOSE.
#  * cmd has 'command' and 'zones' fields, as in the unsigned JSON structure.
#  * kid holds the key identity for which the command is being requested.
#
def run_command (cmd, kid):
	#
	# Per-command access control
	command = cmd ['command']
	zones   = cmd ['zones'  ]
	if not handler.has_key (command):
		# Unrecognised command
		return None
	welcome = False
	welcome = welcome or (acls.has_key (  '*'  ) and kid in acls [  '*'  ])
	welcome = welcome or (acls.has_key (command) and kid in acls [command])
	if not welcome:
		# Refused by ACLs
		return None
	#
	# Invoke command-specific handler without further restraint
	retval = {
		RES_OK:       [ ],
		RES_INVALID:  [ ],
		RES_ERROR:    [ ],
		RES_BADSTATE: [ ],
	}
	hdl = handler [command]
	for zone in zones:
		zone = zone.lower ()
		if not dnsre.match (zone):
			result = RES_ERROR
		elif flagged_invalid (zone):
			result = RES_INVALID
		else:
			result = hdl (zone, kid) 
			if result != RES_INVALID and flagged_invalid (zone):
				result = RES_INVALID
		retval [result].append (zone)
	for result in retval.keys ():
		if len (retval [result]) == 0:
			del retval [result]
	return retval

