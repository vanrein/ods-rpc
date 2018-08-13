# backksm.py -- Adding and removing zones with ksmutil / ods-enforcer backend.
#
# This is where you cause managing and unmanaging of zones.
# The implementation is through zone additional and removal with ods-ksmutil.
#
# The routines return 0 on success, nonzero on failure.
#
# From: Rick van Rein <rick@openfortress.nl>


import os


zone_input_dir = '/var/opendnssec/unsigned'
zone_output_dir = '/var/named/chroot/var/named/opendnssec'


#
# API routine: add a zone to keyed management, return zero on success
#
# Note: ods-ksmutil should output the new zonelist.xml, usable for ods-signer
#
def manage_zone (zone):
	# cmd = 'ods-ksmutil zone add --zone "' + zone + '" -i "' + zone_input_dir + '/' + zone + '.axfr" -o "' + zone_output_dir + '/' + zone + '" -p SURFdomeinen'
	cmd = '/usr/local/surfdomeinen/sbin/zone_add "' + zone + '"'
	return os.system ('sudo ' + cmd)

#
# API routine: remove a zone from keyed management, return zero on success
#
# Note: ods-ksmutil should output the new zonelist.xml, usable for ods-signer
#
def unmanage_zone (zone):
	# cmd = 'ods-ksmutil zone delete --zone "' + zone + '"'
	cmd = '/usr/local/surfdomeinen/sbin/zone_del "' + zone + '"'
	return os.system ('sudo ' + cmd)


#
# API routine: notify other cluster nodes, if any, about a new flag state
#
# This routine is provided the path of the file that is being updated.
# This path can be used to retrieve the current value and/or timestamps.
#
def cluster_update (zone_flag, value, path):
	return True

