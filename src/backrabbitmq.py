# backrabbitmq.py -- Adding and removing zones via Rabbit MQ messaging.
#
# This is where you cause managing and unmanaging of zones.
# The implementation is through sending commands to a queue:
#  - ADDKEY zone.tld
#  - DELKEY zone.tld
# These will be sent to a local queue named keyops.  The reason
# the queue is local is that ods-rpc does not distribute the
# operations; PKCS #11 replication cares for replication.  Also
# note that, beyond key management, there is no work for zone
# addition and removal, because that is done via rsync zone file
# updates (including additions and removals of zone files).
#
# The rabbitdnssec library from RabbitDNSSEC is used here.  This is
# done to be able to share configuration variables and thus to avoid
# the need for double configurations and the management errors that
# would come from it.  Note that the RPC directory is still set in
# two places; it does not only impact this backend, and so it would
# burden non-RabbitMQ generic code with the RabbitDNSSEC library.
#
# The routines return 0 on success, nonzero on failure.
#
# From: Rick van Rein <rick@openfortress.nl>


import os
import sys
import socket
import ssl

import pika


import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical


cfg = rabbitdnssec.my_config ()
# When used with RabbitDNSSEC, this should always be 'key_ops':
routing_key = cfg.get ('routing_key', 'key_ops')
username = cfg ['username']
exchange_name = rabbitdnssec.my_exchange ()


creds   = rabbitdnssec.my_credentials (ovr_username=username)
cnxparm = rabbitdnssec.my_connectionparameters (
cnx = None
chan = None
try:
        cnx = pika.BlockingConnection (cnxparm)
        chan = cnx.channel ()
	log_info ('Ready to start sending to RabbitMQ')
except pika.exceptions.AMQPChannelError, e:
	log_debug ('AMQP Channel Error:', e)
        sys.exit (1)
except pika.exceptions.AMQPError, e:
	log_error ('AMQP Error:', e)
        sys.exit (1)

# Confirm delivery with the return value from chan.basic_publish()
#
chan.confirm_delivery ()

#
# API routine: add a zone to keyed management, return zero on success
#
def manage_zone (zone):
	cmd = 'ADDKEY ' + zone
	try:
		log_debug ('Sending to exchange', exchange_name, 'routing_key', routing_key, 'body', cmd)
		ok = chan.basic_publish (exchange=exchange_name,
                                        routing_key=routing_key,
                                        body=cmd,
					mandatory=True)
		log_debug ('Send success is', ok)
		retval = 0 if ok else 1
	except pika.exceptions.AMQPChannelError, e:
		log_error ('AMQP Channel Error:', e)
		retval = 1
	except pika.exceptions.AMQPError, e:
		log_error ('AMQP Error:', e)
		retval = 1
	except Exception, e:
		log_error ('Exception during AMQP send:', e, 'for zone', zone, 'during ADDKEY')
		retval = 1
	return retval

#
# API routine: remove a zone from keyed management, return zero on success
#
def unmanage_zone (zone):
	cmd = 'DELKEY ' + zone
	try:
		log_debug ('Sending to exchange', exchange_name, 'routing_key', routing_key, 'body', cmd)
		ok = chan.basic_publish (exchange=exchange_name,
                                        routing_key=routing_key,
                                        body=cmd,
					mandatory=True)
		log_debug ('Send success is', ok)
		retval = 0 if ok else 1
	except pika.exceptions.AMQPChannelError, e:
		log_error ('AMQP Channel Error:', e)
		retval = 1
	except pika.exceptions.AMQPError, e:
		log_error ('AMQP Error:', e)
		retval = 1
	except Exception, e:
		log_error ('Exception during AMQP send:', e, 'for zone', zone, 'during DELKEY')
		retval = 1
	return retval


# Not here: The client will want the connection open
#
# if chan is not None:
# 	chan = None
# if cnx is not None:
# 	cnx.close ()
# cnx = None
# 

