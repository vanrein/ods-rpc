# backp11.py -- Adding and removing zones with PKCS #11 and zones.xml.
#
# This is where you cause managing and unmanaging of zones.
# This implementation is an alternative to the full-blown ksmutil / ods-enforcer.
# It maintains its data on the PKCS #11 repository and constructs the zones.xml
# file that is used by ods-signer as input.
#
# TODO: It may also need to connect to ods-signerd to signal immediate action.
#
# The routines return 0 on success, nonzero on failure.
#
# NOTE: The PyKCS11 package used here falls under GPLv2, which spreads to all
#       code, thus reducing your rights as a user to use this software as you
#	please.  This is why at least this version of backp11.py is not
#	likely to be part of the master branch of ods-rpc.
#
# From: Rick van Rein <rick@openfortress.nl>



#
# The location of zones.xml -- not configured, but hard-coded into OpenDNSSEC
#
zones_xml = './zones.xml'

#
# The location of the OpenDNSSEC conf.xml file -- holding HSM and PIN
#
conf_xml = './conf.xml'
# conf_xml = '/etc/opendnssec/conf.xml'

#
# The directory with signconf files, unsigned and signed zone files
#
signconf_dir = '/var/opendnssec/signconf'
unsigned_dir = '/var/opendnssec/unsigned'
signed_dir = '/var/opendnssec/signed'


#
# Configuration ends -- normal import and script statements follow
#
import os
import sys
import time
import random

import PyKCS11

from xml.etree import ElementTree


#
# Global configuration -- curve names and their mapping to DNS and PKCS #11
#
oidP256 = ''.join ([ chr(c) for c in [ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 ] ])
oidP384 = ''.join ([ chr(c) for c in [ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 ] ])
# Map curve names to (algid, ecparams)
curves = {
	"P-256": (13, oidP256),
	"P-384": (14, oidP384),
}



#
# Parse the conf_xml file and store the HSM data as a list of dicts in hsmdescr
#
hsmdescr = None
def parse_hsmdescr ():
	conf = ElementTree.parse (conf_xml)
	root = conf.getroot ()
	assert (root.tag == 'Configuration')
	hsmlist = root.findall ('RepositoryList/Repository')
	if len (hsmlist) < 1:
		raise Exception ('Missing HSM declaration')
	if len (hsmlist) > 1:
		# We report it once here, and repeatedly make the mistake later
		sys.stderr.write ('Using the first HSM from multiple listed\n')
	hsmdl = []
	for hsm in hsmlist:
		descr = { }
		for field in hsm:
			descr [field.tag] = field.text
		hsmdl.append (descr)
	global hsmdescr
	hsmdescr = hsmdl

#
# Ensure having a session to the first HSM in hsmdescr.
#
# When fun is provided, an attempt is made to call fun (session, *args), with
# retry if the session must be re-established.  This form is very useful in
# the beginning of a sequence of operations on PKCS #11 because it hides any
# restart of PKCS #11 sessions.  Since tokens may be ripped out, this is
# a pleasant thing to hide -- in those first operations in any sequence.
#
# When no fun is provided (or if it is set to None), the return value
# shall be the current session.  In this case, the return of None is an
# error.  In fact, None should never be returned as errors lead to an
# exception being raised.
#
p11lib = None
def p11_have_session (fun=None, *args):
	global hsmdescr
	global session
	if hsmdescr is None:
		parse_hsmdescr ()
		session = None
	# First try the function call (if asked) (if we already have a session)
	if (fun is not None) and (session is not None):
		try:
			return fun (session, *args)	# Normal result returned
		except PyKCS11.PyKCS11Error, e:
			if e.value not in [ PyKCS11.CKR_SESSION_CLOSED,
					    PyKCS11.CKR_SESSION_HANDLE_INVALID,
					    PyKCS11.CKR_DEVICE_REMOVED,
					    PyKCS11.CKR_TOKEN_NOT_PRESENT,
					    PyKCS11.CKR_USER_NOT_LOGGED_IN ]:
				raise
		# else continue by reopening and making the call again
	# Open a rd/wr session to the PKCS #11 repository
	global p11lib
	if p11lib is None:
		p11tmp = PyKCS11.PyKCS11Lib ()
		p11tmp.load (hsmdescr [0] ['Module'])
		p11lib = p11tmp
	slot_found = None
	for slot in p11lib.getSlotList ():
		tk = p11lib.getTokenInfo (slot)
		if tk is None:
			continue
		if tk.label == (hsmdescr [0] ['TokenLabel'] + ' '*32) [:32]:
			if slot_found is not None:
				raise Exception ('Multiple PKCS #11 tokens match the label')
			else:
				slot_found = slot
	if slot_found is None:
		raise Exception ('No suitable PKCS #11 token found')
	session = p11lib.openSession (slot_found, PyKCS11.CKF_RW_SESSION)
	session.login (hsmdescr [0] ['PIN'], PyKCS11.CKU_USER)
	# Now repeat the function call (if asked) or return the session
	if (fun is not None) and (session is not None):
		return fun (session, *args)	# Normal result is returned
	else:
		return session  		# Should never be None

#
# Parse the zones.xml file into globalvar zones_etree
#
zones_etree = None
def parse_zones_etree ():
	global zones_etree
	zones_etree =  ElementTree.parse (zones_xml)

#
# Construct globalvar zones_etree from PKCS #11
#
# When zones_etree has been loaded before, that is when it is not None,
# then this becomes a merging action; any new zones found in PKCS #11 will
# be added to the list of managed zones.
#
# If no workable session has been opened, then this routine will open one.
#
def p11load_zones_etree ():
	global zones_etree
	#
	# Find the private key objects in PKCS #11
	seekit = [	( PyKCS11.CKA_CLASS,	PyKCS11.CKO_PRIVATE_KEY ),
			( PyKCS11.CKA_TOKEN,	True ),
			( PyKCS11.CKA_SIGN,	True ) ]
	sought = p11_have_session (PyKCS11.Session.findObjects, seekit)
	# 
	# Check each private key label to be a (possibly empty) list of zones
	# The Enfocer labels will be put up for mapping to this notation
	p11map_id2zones = {}
	map_id2zones = {}
	for i in range (len (sought)):
		found = sought [i].to_dict ()
		if not found.has_key ('CKA_ID'):
			raise Exception ('Private key without CKA_ID -- that must be a failure')
		if not found.has_key ('CKA_LABEL'):
			raise Exception ('Private key without CKA_LABEL -- that must be a failure')
		cka_id = found ['CKA_ID']
		cka_label = found ['CKA_LABEL']
		id2label = ''.join ([ '%02x' % d for d in cka_id ])
		if len (cka_label) == 32 and cka_label == id2label:
			# Need to map this label to a zone list
			map_id2zones [cka_label] = []
		elif not all (['.' in z for z in cka_label.split ()]):
			raise Exception ('Unrecognised CKA_LABEL syntax: ' + cka_label)
		else:
			p11map_id2zones [id2label] = cka_label.split ()
	#
	# Iterate over zones in the signconf directories, to map key labels
	done_sth = False
	fail_sth = False
	for sigco_xml in os.listdir (signconf_dir):
		if not sigco_xml.endswith ('.xml'):
			continue
		sigco_tree = ElementTree.parse (signconf_dir + '/' + sigco_xml)
		sigco_root = sigco_tree.getroot ()
		assert (sigco_root.tag == 'SignerConfiguration')
		for z in sigco_root.findall ('Zone'):
			znm = z.get ('name')
			for kl in z.findall ('Keys/Key/Locator'):
				if p11map_id2zones.has_key (kl.text):
					print 'Already mapped', kl.text
				elif  map_id2zones.has_key (kl.text):
					map_id2zones [kl.text].append (znm)
					done_sth = True
				else:
					print 'No mapping for', kl.text
					fail_sth = True
	# We now have a map_id2zones [keyid] = [ zone0, zone1, ... ]
	# If we modified map_id2zones, we have done_sth and fail_sth if we failed
	print 'DEBUG: done_sth =', done_sth
	print 'DEBUG: fail_sth =', fail_sth
	if fail_sth:
		raise Exception ('Found signconf outside the knowledge of PKCS #11')
	if [] in map_id2zones.values ():
		#TODO# Should we fail now?  Demanding a cleanup first???
		print 'Not all PKCS #11 keys are accounted for by signconf files:'
		for kid in map_id2zones.keys ():
			if map_id2zones [kid] == []:
				print ' * ' + kid
		print 'Ignoring this while constructing zones list from PKCS #11, as you probably just need to cleanup'
	elif done_sth:
		# We made some mappings, so update the CKA_LABEL and pull them in
		raise NotImplementedError ('We might now migrate Enforcer zones to ods-rpc zones, except that PyKCS11 does not support C_SetAttributeValues() for changing CKA_LABEL accordingly')
		#TODO# The code for this clauses is unfinished, and untested
		for kid in map_id2zones.keys ():
			binkid = kid.decode ('hex')
			new_label = ''.join (map_id2zones [kid])
			relabel_tmpl = [ ( PyKCS11.CKA_ID, binkid ) ]
			candidates = session.findObjects (relabel_tmpl)
			for obj in candidates:
				if session.getAttributeValue (obj, ['CKA_CLASS'] in [ [PyKCS11.CKO_PRIVATE_KEY], [PyKCS11.CKO_PUBLIC_KEY] ] ):
					new_tmpl = [ (PyKCS11.CKA_LABEL, new_label) ]
					#TODO# Consider removal of zone with KSM
					#TODO# Start zone management
					for z in map_id2zones [kid]:
						err = zonefile_addkey (z, binkid)
					session.setAttributeValue (obj, new_tmpl)
	# Now construct zones_etree based on p11map_id2zones
	print 'DEBUG: Mappings found in PKCS #11 are:'
	for kid in p11map_id2zones.keys ():
		print 'DEBUG:', kid, '=>', ', '.join (p11map_id2zones [kid])
	if zones_etree is None:
		zones_etree = ElementTree.fromstring ('<ZoneList/>')
	zetzones = {}
	p11map_id2zones ['TODO:REMOVE'] = [ 'DEBUG.vanrein.org', 'DEBUG.ARPA2.net' ]
	for zl in p11map_id2zones.values ():
		for z in zl:
			zonx = None
			for i in zones_etree.findall ('Zone'):
				if i.get ('name') == z:
					zonx = i
					break
			if zonx is None:
				#TODO# Start managing zone z instead of just
				zonefile_addzone (z, writeout=False)
	write_zones_etree ()
	print 'DEBUG: Constructed zoneslist.xml after merging with PKCS #11 is:'
	ElementTree.dump (zones_etree)

#
# Write out globalvar zones_etree to zones.xml file
#
def write_zones_etree ():
	global zones_etree
	assert (zones_etree is not None)
	print 'DIR:', dir (zones_etree), '::', type (zones_etree)
	zones_etree.write (zones_xml + '.new')
	os.rename (zones_xml + '.new', zones_xml)

#
# Add an entry to zones_etree and write out the zone file unless writeout==False
#
def zonefile_addzone (zone, writeout=True):
	global zones_etree
	zonx = ElementTree.SubElement (zones_etree, 'Zone', { 'name': zone } )
	pol  = ElementTree.SubElement (zonx, 'Policy')
	sc   = ElementTree.SubElement (zonx, 'SignerConfiguration')
	adp  = ElementTree.SubElement (zonx, 'Adapters')
	adi  = ElementTree.SubElement (adp, 'Input')
	adif = ElementTree.SubElement (adi, 'File')
	ado  = ElementTree.SubElement (adp, 'Output')
	adof = ElementTree.SubElement (ado, 'File')
	pol .text = 'follow_pkcs11'
	sc  .text = signconf_dir + '/' + zone + '.xml'
	adif.text = unsigned_dir + '/' + zone + '.axfr'
	adof.text = signed_dir + '/' + zone
	if writeout:
		write_zones_etree ()

#
# Remove an entry from the zone list zones_etree and, by default, write out
#
def zonefile_delzone (zone, writeout=True):
	global zones_etree
	root = zones_etree.getroot ()
	done = False
	for zonode in root.findall ('Zone'):
		if zonode.get ('name') == zone:
			zones_etree.remove (zonode)
			done = True
			break
	if not done:
		raise Exception ('Zone ' + zone + ' not found, so removal is not possible')
	if writeout:
		write_zones_etree ()

#
# Construct a CKA_ID in hex, BCD format is YYYYMMDDhhmmssuuuuuu
#
def new_cka_id_hex ():
	def int2bcd (intval, bcdcount):
		retval = ''
		while bcdcount > 0:
			decval = intval % 100
			intval = intval / 100
			hexval = (decval / 10) * 16 + (decval % 10)
			retval = chr (hexval) + retval
			bcdcount = bcdcount - 2
		assert (bcdcount == 0)
		assert (intval == 0)
		return retval
	now = time.time ()
	now_int = int (now)
	now_us = int (1000000 * (now - now_int))
	(now_year, now_month, now_day, now_hour, now_min, now_sec) = time.localtime (now_int) [:6]  
	now_bcd = int2bcd (now_year, 4) + int2bcd (now_month, 2) + int2bcd (now_day, 2) + int2bcd (now_hour, 2) + int2bcd (now_min, 2) + int2bcd (now_sec, 2) + int2bcd (now_us, 6)
	cka_id = now_bcd
	return cka_id.encode ('hex')

#
# Create a new key over PKCS #11, and create a signconf file for it as well.
# Return the new key's CKA_ID in hexadecimal format.
#
def p11_newkey (zone, curvename='P-256'):
	# Determine algorithm parameters
	(dns_algid, p11_ecparams) = curves (curvename)
	# Create a fresh CKA_ID value
	cka_id_hex = new_cka_id_hex ()
	# Generate a random salt and cka_id extension
	prng = random.Random ()
	salt = ''.join ([ chr (int (prng.uniform (0, 256))) for i in range(16) ])
	xtid = '%08x' % prng.uniform (0, 4294967296)
	cka_id_hex = cka_id_hex + xtid
	# Create a fresh ECDSA key pair
	ckm_ecdsa = PyKCS11.Mechanism (PyKCS11.CKM_ECDSA_KEY_PAIR_GEN, None)
	pubtmpl = [
		( PyKCS11.CKA_CLASS,            PyKCS11.CKO_PUBLIC_KEY ),
		( PyKCS11.CKA_EC_PARAMS,        p11_ecparams ),
		( PyKCS11.CKA_LABEL,            zone ),
		( PyKCS11.CKA_ID,               cka_id ),
		( PyKCS11.CKA_KEY_TYPE,         PyKCS11.CKK_ECDSA ),
		( PyKCS11.CKA_VERIFY,           True ),
		( PyKCS11.CKA_ENCRYPT,          False ),
		( PyKCS11.CKA_WRAP,             False ),
		( PyKCS11.CKA_TOKEN,            True ),
	]
	privtmpl = [
		( PyKCS11.CKA_CLASS,            PyKCS11.CKO_PRIVATE_KEY ),
		( PyKCS11.CKA_LABEL,            zone ),
		( PyKCS11.CKA_ID,               cka_id ),
		( PyKCS11.CKA_KEY_TYPE,         PyKCS11.CKK_ECDSA ),
		( PyKCS11.CKA_SIGN,             True ),
		( PyKCS11.CKA_DECRYPT,          False ),
		( PyKCS11.CKA_UNWRAP,           False ),
		( PyKCS11.CKA_SENSITIVE,        True ),
		( PyKCS11.CKA_TOKEN,            True ),
		( PyKCS11.CKA_PRIVATE,          True ),
		( PyKCS11.CKA_EXTRACTABLE,      False ),
	]
	(pubkey, privkey) = p11_have_session (PyKCS11.Session.generateKeyPair, pubtml, privtml, ckm_ecdsa)
	signconf = """<SignerConfiguration>
	<Zone name='""" + zone + """'>
                <Signatures>
                        <Resign>PT7200S</Resign>
                        <Refresh>PT259200S</Refresh>
                        <Validity>
                                <Default>PT604800S</Default>
                                <Denial>PT604800S</Denial>
                        </Validity>
                        <Jitter>PT43200S</Jitter>
                        <InceptionOffset>PT3600S</InceptionOffset>
                </Signatures>
                <Denial>
                        <NSEC3>
                                <Hash>
                                        <Algorithm>1</Algorithm>
                                        <Iterations>5</Iterations>
                                        <Salt>""" + salt.encode ('hex') + """</Salt>  
                                </Hash>
                        </NSEC3>
                </Denial>
                <Keys>
                        <TTL>PT3600S</TTL>
                        <Key>
                                <Flags>257</Flags>
                                <Algorithm>""" + str (dns_algid) + """</Algorithm>
                                <Locator>""" + cka_id_hex + """</Locator>
                                <KSK/>
                                <ZSK/>
                                <Publish/>
                        </Key>
                </Keys>
                <SOA>
                        <TTL>PT3600S</TTL>
                        <Minimum>PT3600S</Minimum>
                        <Serial>datecounter</Serial>
                </SOA>
        </Zone>\n</SignerConfiguration>\n"""
	scname = signconf_dir + '/' + zone + '.xml'
	sc = open (scname + '.new', 'w')
	sc.write (signconf)
	sc.close ()
	os.rename (scname + '.new', scname)
	return cka_id_hex


#
# API routine: add a zone to keyed management, return zero on success
#
def manage_zone (zone):
	cka_id_hex = p11_newkey (zone)
	err = (cka_id is None)
	if err == 0:
		err = zonefile_addzone (zone, cka_id_hex)
	return err

#
# API routine: remove a zone from keyed management, return zero on success
#
def unmanage_zone (zone):
	keys = zonefile_getkeys (zone)
	err = (keys is None)
	for k in keys:
		if err == 0:
			err = p11_delkey (zone, k)
	if err == 0:
		err = zonefile_delzone (zone)
	return err


if __name__ == '__main__':
	p11load_zones_etree ()
