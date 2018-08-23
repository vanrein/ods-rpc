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
import time
import ssl

import threading

import pika


import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical


cfg = rabbitdnssec.my_config ('ods-rpc')
# When used with RabbitDNSSEC, this should always be 'key_ops':
routing_key = cfg.get ('routing_key', 'key_ops')
cluster_key = cfg.get ('cluster_key', '')  # '' means no clustering
username = cfg ['username']
rpcdir = cfg.get ('rpc_dir', '/var/opendnssec/rpc')
exchange_name = rabbitdnssec.my_exchange ()
cluster_queue = rabbitdnssec.my_queue (cluster_key)


creds   = rabbitdnssec.my_credentials (ovr_username=username)
cnxparm = rabbitdnssec.my_connectionparameters (creds, blocked_connection_timeout=0)
cnx = None
chan = None

def have_channel ():
	global creds, cnxparm, cnx, chan
	if chan is None or not chan.is_open:
		try:
			cnx = pika.BlockingConnection (cnxparm)
			chan = cnx.channel ()
			chan.confirm_delivery ()
			log_info ('Prepared to start sending to RabbitMQ')
		except pika.exceptions.AMQPChannelError, e:
			log_debug ('AMQP Channel Error:', e)
			sys.exit (1)
		except pika.exceptions.AMQPError, e:
			log_error ('AMQP Error:', e)
			sys.exit (1)
	return chan

#
# API routine: add a zone to keyed management, return zero on success
#
def manage_zone (zone):
	cmd = 'ADDKEY ' + zone
	chan = have_channel ()
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
	finally:
		chan = None
		cnx.close ()
		cnx = None
	return retval

#
# API routine: remove a zone from keyed management, return zero on success
#
def unmanage_zone (zone):
	cmd = 'DELKEY ' + zone
	chan = have_channel ()
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
	finally:
		chan = None
		cnx.close ()
		cnx = None
	return retval

#
# API routine: notify other cluster nodes, if any, about a new flag state
#
def cluster_update (zone_flag, value):
	if cluster_key == '':
		# No action towards a cluster
		return True
	chan = have_channel ()
	log_debug ('cluster_update (' + str (zone_flag) + ', ' + str (value) + ')')
	now = int (time.time ())
	if value is False or value is None:
		cmd = str (now) + ' CLEAR ' + zone_flag + ' '
	elif value is True:
		cmd = str (now) + ' SET '   + zone_flag + ' '
	else:
		# String values are distinct from True by an added newline
		cmd = str (now) + ' SET '   + zone_flag + ' ' + str (value) + '\n'
	log_debug ('cluster_update command is "' + cmd + '"')
	try:
		log_debug ('Sending to exchange', exchange_name, 'cluster_key', cluster_key, 'body', cmd)
		ok = chan.basic_publish (exchange=exchange_name,
                                        routing_key=cluster_key,
                                        body=cmd,
					mandatory=True)
		log_debug ('Send success is', ok)
		retval = ok
	except pika.exceptions.AMQPChannelError, e:
		log_error ('AMQP Channel Error:', e)
		retval = False
	except pika.exceptions.AMQPError, e:
		log_error ('AMQP Error:', e)
		retval = False
	except Exception, e:
		log_error ('Exception during AMQP send:', e, 'for zone', zone, 'during ADDKEY')
		retval = False
	finally:
		chan = None
		cnx.close ()
		cnx = None
	return retval


# Process updates from other cluster nodes
#
cluster_start = int (time.time ())
#
def process_cluster_msg (chan, msg, props, body):
	log_debug ('Processing cluster message', body)
	try:
		(time_str,cmd,zone_flag,value) = body.split (' ',3)
		time_int = int (time_str)
		flag_path = rpcdir + '/' + os.sep + zone_flag
		if cmd == 'CLEAR':
			if os.stat (rpcdir).st_mtime < time_str:
				os.unlink (flag_path)
				log_debug ('Removed RPC flag', zone_flag)
		elif cmd == 'SET':
			#TODO# Check timestamp
			try:
				go4it = os.stat (flag_path).st_mtime < time_str
			except OSError, ose:
				go4it = ose.errno == 2
			if go4it:
				open (flag_path, 'w').write (value)
				log_debug ('Set RPC flag', zone_flag, 'to', value)
		else:
			raise Exception ('Unknown command')
		chan.basic_ack (delivery_tag=msg.delivery_tag)
		return True
	except Exception,e:
		log_error ('Failed to process cluster message', body, 'due to', str (e))
		return False
#
class ClusterRecipient (threading.Thread):
	#
	def __init__ (self):
		# BlockConnection is not thread-safe, so we open our own
		self.cnx = None
		self.chan = None
		try:
			self.cnx = pika.BlockingConnection (cnxparm)
			self.chan = self.cnx.channel ()
			log_info ('Prepared to start reading from RabbitMQ')
		except pika.exceptions.AMQPChannelError, e:
			log_debug ('AMQP Channel Error:', e)
			sys.exit (1)
		except pika.exceptions.AMQPError, e:
			log_error ('AMQP Error:', e)
			sys.exit (1)
		threading.Thread.__init__ (self)
		self.setDaemon (True)
	#
	def run (self):
		log_debug ('Starting background cluster message processor')
		self.chan.basic_consume (process_cluster_msg, cluster_queue)
		self.chan.start_consuming ()
		log_debug ('Stopped  background cluster message processor')
#
if cluster_key != '':
	chan = have_channel ()
	log_debug ('Starting to process initial cluster messages')
	while True:
		(msg,props,body) = chan.basic_get (queue=cluster_queue)
		if msg is None:
			break
		process_cluster_msg (chan, msg, props, body)
	log_debug ('Finished processing initial cluster messages')
	cluster_recipient = ClusterRecipient ()
	cluster_recipient.start ()


#
# We always close the channel and connection for AMQP.
# The reason is that is_open does not provide reliable results,
# nor does it work to tell PIKA to veto the timeout.  Our
# software does not pass long-term control to PIKA, so it
# cannot always respond to polling messages, which results
# in the PIKA connection going down after a time of waiting
# for ods-rpc commands.
#
# THIS IS DUE TO EXPERIENCED BUGS IN PIKA, IT IS IMPERFECT.
#
if chan is not None:
	chan = None
if cnx is not None:
	cnx.close ()
cnx = None


log_debug ('RabbitMQ backend is ready for action')

