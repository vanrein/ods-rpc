# genericapi.py -- The command interface for the OpenDNSSEC RPC API
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
import time

from syslog import *

from commandaccess import acls
import localrules
import dnslogic
import backend


# The directory under which the flags are made
flagdir = '/var/opendnssec/rpc'

if not os.path.isdir (flagdir):
	syslog (LOG_CRIT, 'Missing control directory: ' + str (flagdir) + ' (FATAL)')
	sys.exit (1)


# The flagging system; zone name plus flag name; file absense is False
def flagged (zone, flagname, value=None):
	error = False
	flaglong = zone + os.extsep + flagname
	flagfile = flagdir + os.sep + flaglong
	try:
		oldval = open (flagfile, 'r').read ()
		if oldval == '':
			oldval = True
		elif oldval [-1:] == '\n':
			oldval = oldval [:-1]
		else:
			#TODO# error is not really used
			error = 'Illegal old value'
	except IOError, ioe:
		if ioe.errno == 2:
			oldval = False
		else:
			#TODO# error is not really used
			error = str (ioe)
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
	if not error:
		if value is not None and retval != value:
			#TODO# error is not used
			error = 'Disk did not reproduce the flag value as written'
			retval = False
	syslog (LOG_INFO, 'FLAG ' + flagname + ' IS ' + str (retval) + ' :: ' + str (type (retval)) + ' AND SHOULD BE ' + str (value) + ' :: ' + str (type (value)) + ' for zone ' + zone)
	if error:
		# It is abnormal for this to happen
		syslog (LOG_ERR, 'Failed to set ' + flagname + ' flag to ' + str (value) + ' for zone ' + zone + ', cause:', error)
		if flagname != 'invalid' and not flagged (zone, 'invalid', value='Failed to set ' + flagname + ' flag to ' + str (value)):
			syslog (LOG_CRIT, 'In addition, failed to set error flag to True for zone ' + zone + ' (FATAL)')
			sys.exit (1)
	if value != oldval:
		if not backend.cluster_update (flaglong, value):
			syslog (LOG_ERR, 'Failed to update cluster about flag', flagname, 'change from', oldval, 'to', newval)
	syslog (LOG_INFO, 'RETURNING ' + str (retval) + ' FOR ' + flagname + ' ON ' + zone)
	return retval

def flagged_signing (zone, value=None):
	return flagged (zone, 'signing', value)

def flagged_signed (zone, value=None):
	return flagged (zone, 'signed', value)

def flagged_chaining (zone, value=None):
	return flagged (zone, 'chaining', value)

def flagged_chained (zone, value=None):
	return flagged (zone, 'chained', value)

def flagged_waiveds (zone):
	return flagged (zone, 'waiveds')

def flagged_unchained (zone, value=None):
	return flagged (zone, 'unchained', value)

def flagged_unsigning (zone, value=None):
	return flagged (zone, 'unsigning', value)

def flagged_invalid (zone, value=None):
	return flagged (zone, 'invalid', value)

def flagged_dnskeyttl (zone, value=None):
	return flagged (zone, 'dnskeyttl', value)

def flagged_dsttl (zone, value=None):
	return flagged (zone, 'dsttl', value)

def passed (zone, flagname):
	value = flagged (zone, flagname)
	try:
		fromtm = int (str (value))
		return time.time () >= fromtm
	except:
		return False

def passed_signed (zone):
	return passed (zone, 'signed')

def passed_chained (zone):
	return passed (zone, 'chained')

def passed_unchained (zone):
	return passed (zone, 'unchained')

def passed_unsigned (zone):
	return passed (zone, 'unsigned')


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
#TODO# Hacked uppercase in here for Alfa-college.nl
dnsre = re.compile ('^[0-9a-zA-Z]+(-[0-9a-zA-Z]+)*(\.[0-9a-zA-Z]+(-[0-9a-zA-Z])*)+$')


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
	if backend.manage_zone (zone) != 0:
		syslog (LOG_ERR, 'Failed to add zone ' + zone + ' to OpenDNSSEC RPC')
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
		syslog (LOG_INFO, 'LOADED ASSERTED-FROM TIME ' + str (asserted_fromtm) + ' FOR ' + zone)
	except:
		# flagged_invalid (zone, value='Flag signed failed to load as an integer')
		# return RES_INVALID
		asserted_fromtm = None
		syslog (LOG_INFO, 'NO ASSERTED-FROM TIME IN signed FLAG FOR ' + zone + ' YET')
	#
	# Consider the case that no signatures may have been found before;
	# this will check DNS and store a now-plus-TTL in the 'signed' flag
	if asserted_fromtm is None:
		if dnslogic.test_for_signed_dnskey (
				zone,
				#deadlock# dnslogic.PUBLISHER_AUTHORITATIVES |
				dnslogic.PUBLISHER_OPENDNSSEC |
				dnslogic.PUBLISHER_ALL):
			ass1ttl = dnslogic.dnskey_ttl (
					zone,
					dnslogic.PUBLISHER_OPENDNSSEC)
			ass2ttl = dnslogic.negative_caching_ttl (
					zone,
					dnslogic.PUBLISHER_OPENDNSSEC)
			asserted_fromtm = dnslogic.ttl2endtime (
					max (ass1ttl, ass2ttl))
			#
			# Override semantical promise that what we see is
			# signed to the rest of the world.  This semantical
			# version is possible when all DNS passes through
			# OpenDNSSEC (NULL signing alg) or when the client
			# prepares the zone beforehand; neither applies in
			# our case so we were running into a deadlock (see
			# above) and had to limit the semantics to just say
			# that OpenDNSSEC has signed it.  Cache TTL has no
			# real value anymore either, in this case.  So here
			# we go overriding it:
			#
			asserted_fromtm = int (time.time ())
			syslog (LOG_INFO, 'COMPUTED ASSERTED-FROM TIME TO BE ' + str (asserted_fromtm) + ' BASED ON ' + str (ass1ttl) + ' AND ' + str (ass2ttl) + ' FOR ' + zone)
			if asserted_fromtm is not None:
				flagged_signed (zone, value=str (asserted_fromtm))
			else:
				syslog (LOG_ERR, 'Failed to determine endtime in OpenDNSSEC RPC during assert_signed on ' + zone)
				return RES_ERROR
		else:
			syslog (LOG_INFO, 'STILL FOUND NO DNSKEY RECORDS FOR ' + zone)
			syslog (LOG_INFO, 'Failed to assert that zone ' + zone + ' is published-signed')
			return RES_ERROR
	#
	# Now test the asserted_fromtm value
	if time.time () >= asserted_fromtm:
		syslog (LOG_INFO, 'ENDED COUNTDOWN FOR ' + zone + ' UNTIL ' + str (asserted_fromtm))
		return RES_OK
	else:
		syslog (LOG_INFO, 'STILL DOING COUNTDOWN FOR ' + zone + ' UNTIL ' + str (asserted_fromtm))
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
			syslog (LOG_ERR, 'Failed to set chaining flag on zone ' + zone)
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
		syslog (LOG_INFO, 'LOADED CHAINED ASSERTED-FROM TIME ' + str (asserted_fromtm))
	except:
		# flagged_invalid (zone, value='Flag chained failed to load as an integer')
		syslog (LOG_INFO, 'NO CHAINED ASSERTED-FROM TIME YET FOR ' + zone)
		asserted_fromtm = None
	#
	# The DS records may be absent, which is a sign that we need to
	# back off and retry later; this can happen when another process
	# handles the submission of DS with delays
	if not dnslogic.have_ds (zone):
		if flagged_waiveds (zone):
			syslog (LOG_WARNING, 'HACK IN PLACE: WAIVEDS FLAGGED FOR ' + zone)
		else:
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
			syslog (LOG_INFO, 'COMPUTED CHAINED ASSERTED-FROM TIME ' + str (asserted_fromtm) + ' FROM ' + str (ass1tm) + ' AND ' + str (ass2tm))
			if asserted_fromtm is not None:
				flagged_chained (zone, value=str (asserted_fromtm))
			else:
				return RES_ERROR
		else:
			return RES_ERROR
	#
	# Now test the asserted_fromtm value
	if time.time () >= asserted_fromtm:
		syslog (LOG_INFO, 'PASSED ACROSS THE CHAINED ASSERTED-FROM TIME ' + str (asserted_fromtm))
		return RES_OK
	else:
		syslog (LOG_INFO, 'COUNTING DOWN TO THE CHAINED ASSERTED-FROM TIME ' + str (asserted_fromtm))
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
			syslog (LOG_ERR, 'Failed to clear chained/chaining flags on zone ' + zone)
			return RES_INVALID
	else:
		syslog (LOG_ERR, 'Failed in localrules.chain_stop() on zone ' + zone)
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
		dsttlend = int (flagged_unchained (zone))
	except:
		dsttlend = dnslogic.ttl2endtime (dsttl)
		flagged_unchained (zone, value=dsttlend)
	if time.time () < dsttlend:
		# We need to wait somewhat longer
		return RES_ERROR
	else:
		# The flagged_unchained time has passed
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
		syslog (LOG_INFO, 'FLAGS ARE OFF -- BADSTATE')
		return RES_BADSTATE
	dnskeyttl = dnslogic.dnskey_ttl (
				zone,
				dnslogic.PUBLISHER_OPENDNSSEC)
	if flagged_dnskeyttl (zone, value=str (dnskeyttl)) != str (dnskeyttl):
		return RES_INVALID
	if not localrules.sign_stop (zone):
		return RES_ERROR
	if backend.unmanage_zone (zone) != 0:
		syslog (LOG_ERR, 'Failed to remove zone ' + zone + ' from OpenDNSSEC RPC')
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
		syslog (LOG_INFO, 'Failed to assert that zone ' + zone + ' is published-unsigned')
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
		syslog (LOG_INFO, 'CREATED TTLEND FOR DNSKEY: ' + str (dnskeyttlend))
		flagged_unsigning (zone, value=str (dnskeyttlend))
	else:
		dnskeyttlend = int (unsigning)
		syslog (LOG_INFO, 'GOT TTLEND FOR DNSKEY: ' + str (dnskeyttlend))
	if time.time () < dnskeyttlend:
		# The countdown has not yet completed, so tick a little more
		syslog (LOG_INFO, 'AWAITING COUNTDOWN UNTIL: ' + str (dnskeyttlend))
		return RES_ERROR
	else:
		# The countdown is complete, so cleanup flags and report success
		syslog (LOG_INFO, 'COMPLETED COUNTDOWN UNTIL: ' + str (dnskeyttlend))
		if flagged_signing (zone, value=False):
			return RES_INVALID
		flagged_dsttl (zone, value=False)
		flagged_dnskeyttl (zone, value=False)
		flagged_unsigning (zone, value=False)
		return RES_OK

#
# The goto_xxx commands jump around the state diagram until a desired state
# is reached.  They may need to be called multiple times, so through polling,
# until they can return a positive response.  They add nothing but simplicity
# of operation to the foregoing commands.
#

def do_goto_signed (zone, kid):
	rv = RES_OK
	syslog (LOG_INFO, 'goto_signed ' + zone)
	if rv == RES_OK and passed_signed (zone):
		if flagged_chaining (zone) or flagged_chained (zone):
			# syslog (LOG_INFO, 'goto_signed --> gosub_unchained')
			# rv = do_goto_unchained (zone, kid)
			syslog( LOG_INFO, 'goto_signed --> client error, already chained/chaining, invalidating zone')
			flagged_invalid (zone, value='Attempting goto_signed on ' + zone + ' which already progressed to chaining')
			rv = RES_INVALID
		else:
			syslog (LOG_INFO, 'goto_signed --> assert_unchained')
			rv = do_assert_unchained (zone, kid)
	if rv == RES_OK and not flagged_signing (zone) and not flagged_signed (zone):
		#USELESS# syslog (LOG_INFO, 'goto_signed --> sign_start')
		#USELESS# rv = do_sign_start (zone, kid)
		syslog (LOG_INFO, 'goto_signed --> sign_approve')
		rv = do_sign_approve (zone, kid)
	if rv == RES_OK:
		syslog (LOG_INFO, 'goto_signed --> assert_signed')
		rv = do_assert_signed (zone, kid)
	syslog (LOG_INFO, 'goto_signed := ' + str (rv))
	return rv

def do_goto_chained (zone, kid):
	rv = RES_OK
	syslog (LOG_INFO, 'goto_chained ' + zone)
	if rv == RES_OK and not passed_signed (zone):
		syslog (LOG_INFO, 'goto_chained --> gosub_signed')
		rv = do_goto_signed (zone, kid)
	if rv == RES_OK and flagged_signing (zone) and not flagged_chaining (zone):
		syslog (LOG_INFO, 'goto_chained --> chain_start')
		rv = do_chain_start (zone, kid)
	if rv == RES_OK:
		syslog (LOG_INFO, 'goto_chained --> assert_chained')
		rv = do_assert_chained (zone, kid)
	syslog (LOG_INFO, 'goto_chained := ' + str (rv))
	return rv

def do_goto_unchained (zone, kid):
	rv = RES_OK
	syslog (LOG_INFO, 'goto_unchained ' + zone)
	if rv == RES_OK and flagged_chaining (zone) and not passed_chained (zone):
		syslog (LOG_INFO, 'goto_unchained --> gosub_chained')
		rv = do_goto_chained (zone, kid)
	if rv == RES_OK and flagged_chaining (zone) and passed_chained (zone):
		syslog (LOG_INFO, 'goto_unchained --> chain_stop')
		rv = do_chain_stop (zone, kid)
	if rv == RES_OK and not flagged_chaining (zone):
		syslog (LOG_INFO, 'goto_unchained --> assert_unchained')
		rv = do_assert_unchained (zone, kid)
	syslog (LOG_INFO, 'goto_unchained := ' + str (rv))
	return rv

def do_goto_unsigned (zone, kid):
	rv = RES_OK
	syslog (LOG_INFO, 'goto_unsigned ' + zone)
	if rv == RES_OK and flagged_signed (zone):
		if not passed_signed (zone):
			# Complete halfway-done signing before returning
			syslog (LOG_INFO, 'goto_unsigned --> gosub_signed')
			rv = do_goto_signed (zone, kid)
		elif flagged_chained (zone):
			syslog (LOG_INFO, 'goto_unsigned --> gosub_unchained')
			rv = do_goto_unchained (zone, kid)
		else:
			syslog (LOG_INFO, 'goto_unsigned --> assert_unchained')
			rv = do_assert_unchained (zone, kid)
	if rv == RES_OK and flagged_signed (zone) and not flagged_chained (zone):
		#USELESS# rv = do_sign_ignore (zone, kid)
		syslog (LOG_INFO, 'goto_unsigned --> sign_stop')
		rv = do_sign_stop (zone, kid)
	if rv == RES_OK and not flagged_signed (zone):
		syslog (LOG_INFO, 'goto_unsigned --> assert_unsigned')
		rv = do_assert_unsigned (zone, kid)
	syslog (LOG_INFO, 'goto_unsigned := ' + str (rv))
	return rv

#
# The drop_dead command serves a practical use of removing a zone here and now,
# with no questions asked.  Normally, when the zone is present, its removal
# should be instant and positive.  A later retry will fail, of course.
#
# Note that this is a disruptive command; you are willingly and knowingly
# destroying your zone, and risk outages of DNS data because the care of
# the other commands is deliberately bypassed in drop_dead.
#

def do_drop_dead (zone, kid):
	syslog (LOG_INFO, 'drop_dead ' + zone)
	backend.unmanage_zone (zone)
	flagged_signing   (zone, value=False)
	flagged_signed    (zone, value=False)
	flagged_chaining  (zone, value=False)
	flagged_chained   (zone, value=False)
	flagged_dsttl     (zone, value=False)
	flagged_dnskeyttl (zone, value=False)
	flagged_unchained (zone, value=False)
	flagged_unsigning (zone, value=False)
	syslog (LOG_INFO, 'drop_dead := RES_OK')
	return RES_OK

#
# The update_signed command can be called on any zone which is being signed.
# Use it to invoke the command of the same name in the localrules module, where
# you can set it up to do anything you like.  A default action that is suggested
# to incorporate (at least) is to have the zone signed freshly, with
#
#   ods-signer sign <zone>
#

def do_update_signed (zone, kid):
	if not flagged_signed (zone):
		return RES_BADSTATE
	if not localrules.update_signed (zone):
		return RES_ERROR
	else:
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
handler ['goto_signed'     ] = do_goto_signed
handler ['goto_chained'    ] = do_goto_chained
handler ['goto_unchained'  ] = do_goto_unchained
handler ['goto_unsigned'   ] = do_goto_unsigned
handler ['drop_dead'       ] = do_drop_dead
handler ['update_signed'   ] = do_update_signed


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
	syslog (LOG_DEBUG, 'ZONES IN CMD: ' + str (zones))
	if not handler.has_key (command):
		# Unrecognised command
		syslog (LOG_INFO, 'Unrecognised command: ' + command)
		return None
	welcome = False
	welcome = welcome or (acls.has_key (  '*'  ) and kid in acls [  '*'  ])
	welcome = welcome or (acls.has_key (command) and kid in acls [command])
	if not welcome:
		# Refused by ACLs
		syslog (LOG_INFO, 'Refused by ACLs')
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
		syslog (LOG_DEBUG, 'DEBUG ZONE TO LOWER: ' + zone + ' :: ' + str (type (zone)))
		zone = zone.lower ()
		if zone [-1:] == '.':
			zone = zone [:-1]
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

