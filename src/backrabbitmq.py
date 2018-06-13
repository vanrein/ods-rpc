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
# The routines return 0 on success, nonzero on failure.
#
# From: Rick van Rein <rick@openfortress.nl>


import os
import sys
import socket
import ssl

import pika



#
# BEGIN SETTINGS
#

signer_machine = socket.gethostname ().split ('.') [0]
routing_key = 'key_ops'
host = 'localhost'
port = 5671
wrap_tls = True
username = 'odsrpc'
password = 'TODO'
vhost = 'MyNiche'
exchange_name = signer_machine + '_signer'
conf_tls = {
        'ssl_version': ssl.PROTOCOL_TLSv1_2,
        'ca_certs':   '/etc/ssl/certs/mynicheCA.pem',
        'certfile':   '/etc/ssl/certs/' + signer_machine + '.pem',
        'keyfile':    '/root/private/'  + signer_machine + '.pem',
        'server_side': False,
}

#
# END SETTINGS
#


creds = pika.PlainCredentials (username, password)

cnxparm = pika.ConnectionParameters (
        host=host,
        port=port,
        virtual_host=vhost,
        ssl=wrap_tls,
        ssl_options=conf_tls,
        credentials=creds
)
print 'Connection parameters:', cnxparm
cnx = None
chan = None
try:
        cnx = pika.BlockingConnection (cnxparm)
        chan = cnx.channel ()
        print 'Ready to start sending to RabbitMQ'
except pika.exceptions.AMQPChannelError, e:
        print 'AMQP Channel Error:', e
        sys.exit (1)
except pika.exceptions.AMQPError, e:
        print 'AMQP Error:', e
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
		print 'DEBUG: Sending to exchange', exchange_name, 'routing key', routing_key, 'body', cmd
		ok = chan.basic_publish (exchange=exchange_name,
                                        routing_key=routing_key,
                                        body=cmd,
					mandatory=True)
		print ok
		retval = 0 if ok else 1
	except pika.exceptions.AMQPChannelError, e:
		print 'AMQP Channel Error:', e
		retval = 1
	except pika.exceptions.AMQPError, e:
		print 'AMQP Error:', e
		retval = 1
	except Exception, e:
		print 'Exception during AMQP send:', e, 'for zone', zone, 'during ADDKEY'
		retval = 1
	return retval

#
# API routine: remove a zone from keyed management, return zero on success
#
def unmanage_zone (zone):
	cmd = 'DELKEY ' + zone
	try:
		print 'DEBUG: Sending to exchange', exchange_name, 'routing key', routing_key, 'body', cmd
		ok = chan.basic_publish (exchange=exchange_name,
                                        routing_key=routing_key,
                                        body=cmd,
					mandatory=True)
		print ok
		retval = 0 if ok else 1
	except pika.exceptions.AMQPChannelError, e:
		print 'AMQP Channel Error:', e
		retval = 1
	except pika.exceptions.AMQPError, e:
		print 'AMQP Error:', e
		retval = 1
	except Exception, e:
		print 'Exception during AMQP send:', e, 'for zone', zone, 'during DELKEY'
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

