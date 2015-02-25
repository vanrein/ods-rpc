# genericapi.py -- The command interface for the OpenDNSSEC API
#
# This is a general command interface -- it processes a JSON-formatted
# DNSSEC Request and produces a JSON-formatted DNSSEC Request.  Keys and
# signatures are not handled here.
#
# From: Rick van Rein <rick@openfortress.nl>


from commandaccess import acls


# Temporary flagging system; flags are True for zones in the respective set
flagged_signing = [ ]
flagged_chained = [ ]
flagged_error   = [ ]


# Symbolic names for result lists of zones
RES_OK       = 'ok'
RES_ERROR    = 'error'
RES_INVALID  = 'invalid'
RES_BADSTATE = 'badstate'


#
# The individual operations follow, with do_ prefixed to the command name
#

def do_sign_start (zone, kid):
	if zone in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_sign_approve (zone, kid):
	if zone in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# DNS information must be locally available
	flagged_signing.append (zone)
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_assert_signed (zone, kid):
	if zone not in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# Assert presence in OpenDNSSEC and all authoritatives
	from random import Random
	rng = Random ()
	if rng.uniform (0, 1) > 0.3:
		return RES_ERROR
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_chain_start (zone, kid):
	if zone not in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# Assert presence in OpenDNSSEC and all authoritatives
	flagged_chained.append (zone)
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_assert_chained (zone, kid):
	if zone not in flagged_signing or zone not in flagged_chained:
		return RES_BADSTATE
	#TODO# Additional certainties
	from random import Random
	rng = Random ()
	if rng.uniform (0, 1) > 0.3:
		return RES_ERROR
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_chain_stop (zone, kid):
	if zone not in flagged_signing or zone not in flagged_chained:
		return RES_BADSTATE
	#TODO# Parent has DS setup
	flagged_chained.remove (zone)
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_assert_unchained (zone, kid):
	if zone not in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# Additional certainties
	from random import Random
	rng = Random ()
	if rng.uniform (0, 1) > 0.3:
		return RES_ERROR
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_sign_ignore (zone, kid):
	if zone not in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_sign_stop (zone, kid):
	if zone not in flagged_signing or zone in flagged_chained:
		return RES_BADSTATE
	#TODO# Semantics of flagged_signing are unknown
	from random import Random
	rng = Random ()
	if rng.uniform (0, 1) > 0.5:
		flagged_signing.remove (zone)
	#TODO# raise NotImplementedError ()
	return RES_OK

def do_assert_unsigned (zone, kid):
	if                                zone in flagged_chained:
		return RES_BADSTATE
	from random import Random
	rng = Random ()
	if rng.uniform (0, 1) > 0.3:
		return RES_ERROR
	if zone in flagged_signing:
		flagged_signing.remove (zone)
	#TODO# raise NotImplementedError ()
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
		if zone in flagged_error:
			result = RES_ERROR
		else:
			result = hdl (zone, kid) 
		retval [result].append (zone)
	for result in retval.keys ():
		if len (retval [result]) == 0:
			del retval [result]
	return retval
