# commandaccess.py -- Access Control Lists for ods-webapi.
#
# This file lists which key-identifiers (kid) may invoke operations.  By
# doing this separately for each command, there is a possibility of some
# refinement; some actions may be reserved to staff, for instance.
#
# From: Rick van Rein <rick@openfortress.nl>


acls = { }

acls ['*'] = [ 'portal+key1@example.com' ]

acls ['sign_start'] = [ ]
acls ['sign_approve'] = [ ]
acls ['assert_signed'] = [ ]
acls ['chain_start'] = [ ]
acls ['assert_chained'] = [ ]
acls ['chain_stop'] = [ ]
acls ['assert_unchained'] = [ ]
acls ['sign_ignore'] = [ ]
acls ['sign_stop'] = [ ]
acls ['assert_unsigned'] = [ ]

