# dnslogic.py -- Check desired information in DNS
#
# This module provides checks that are executed in DNS, to ensure that data
# is published in all places where they are desired.  For instance, in the
# OpenDNSSEC output name server, in all authoritatives, or in parent zones.
#
# The output DNS server for OpenDNSSEC is setup in the localrules module
# with the ods_output variable.
#
# This code was built against dnspython version 1.11.1, http://www.dnspython.org/
# and it copies some of the resolution code because the code does not support
# asking for DNSSEC signatures in a normal query.  This is a liability when the
# dnspython version is updated, sorry about that.  I do agree that dnspython
# should not have forced me to copy its internal code too.
#
# TODO: We may also need to deal with TTL timers towards our callers.
#
# From: Rick van Rein <rick@openfortress.nl>


import time
import syslog
from math import ceil

from localrules import ods_output, local_resolver

from dns import name, resolver, query, exception
from dns import message, rdatatype, rdataclass, rcode

#
# Values that can be used to indicate a desired publisher
#
PUBLISHER_PARTY_MASK = 0x00f0
PUBLISHER_LOGIC_MASK = 0x000f
#
# Values for the party
#NOT# PUBLISHER_DEFAULT        = 0x0000
PUBLISHER_OPENDNSSEC     = 0x0010
PUBLISHER_AUTHORITATIVES = 0x0020
PUBLISHER_PARENTS        = 0x0030
#
# Indicate whether some or all of the name servers must comply
PUBLISHER_SOME = 0x0001
PUBLISHER_ALL  = 0x0002
PUBLISHER_NONE = 0x0003


#
# Combine results as signaled in PUBLISHER_SOME, _ALL or _NONE:
#
def combine_individual_outcomes (indiv_test_outcomes, publisher):
	if indiv_test_outcomes is None:
		return None
	publisher = publisher & 0x0003
	if   publisher == PUBLISHER_SOME:
		for one in indiv_test_outcomes:
			# Skip None (for not-found info) as if it was False
			if one is True:
				return True
		return False
	elif publisher == PUBLISHER_ALL:
		for one in indiv_test_outcomes:
			if not one is True:
				# Also fails on None (for not-found info)
				return False
		return True
	elif publisher == PUBLISHER_NONE:
		for one in indiv_test_outcomes:
			if not one is False:
				# Also fails on None (for not-found info)
				return False
		return True
	else:
		return False


#
# Collect a list of name servers to be inquired.  If something goes wrong
# while trying to setup the list, return None instead.
#
def list_name_servers (zone, publisher):
	publisher = publisher & 0xfffc
	if   publisher == PUBLISHER_OPENDNSSEC:
		return [ ods_output ]
	elif publisher == PUBLISHER_AUTHORITATIVES:
		rss = local_resolver.query (
				name.from_text (zone),
				rdtype=rdatatype.NS).rrset
		return [ str (rs) for rs in rss ]
	elif publisher == PUBLISHER_PARENTS:
		if not '.' in zone:
			return None
		(child,parent) = zone.split ('.', 1)
		rrs = local_resolver.query (
				name.from_text (parent),
				rdtype=rdatatype.NS).rrset
		return [ str (rs) for rs in rss ]
	else:
		return None

#
# Make a collective query at some source and return the various results
# The answerproc function processes the individual response.answers
#
def collective_query (zone, rrtype, name_servers, answerproc=None):
	if name_servers is None:
		return None
	retval = []
	# For now: Serial query
	for ns in name_servers:
		# Within a NS record, alternative address may be available.
		# We are going to assume that they are equivalent, so any one
		# of the addresses may provide an answer.
		res = resolver.Resolver (configure=False)
		res.use_edns (0, 0, 4096)
		nsas = []
		try:
			for nsa in local_resolver.query (
					name.from_text (ns),
					rdtype=rdatatype.AAAA):
				nsas.append (str (nsa))
		except resolver.NXDOMAIN:
			pass
		try:
			for nsa in local_resolver.query (
					name.from_text (ns),
					rdtype=rdatatype.A):
				nsas.append (str (nsa))
		except resolver.NXDOMAIN:
			pass
		if len (nsas) > 0:
			request = message.make_query (
					name.from_text (zone),
					rrtype,
					rdataclass.IN,
					use_edns=True,
					# endsflags=0,
					payload=4096,
					want_dnssec=True)
			backoff = 0.10
			response = None
			done = False
			start = time.time ()
			timeout = local_resolver._compute_timeout (start)
			while (response is None) and (not done):
				for nsa in nsas:
					try:
						response = query.udp (
								request,
								nsa,
								timeout)
						errcode = response.rcode ()
						if errcode == rcode.NOERROR:
							done = True
							break
						if errcode == rcode.YXDOMAIN:
							raise YXDOMAIN
						if errcode == rcode.NXDOMAIN:
							break
					except:
						response = None
						continue
				try:
					timeout = local_resolver._compute_timeout (start)
				except exception.Timeout:
					done = True
					break
				sleep_time = min (timeout, backoff)
				time.sleep (sleep_time)
				backoff = backoff * 2
			if response is None:
				retval.append (None)
			else:
				print 'Answer is:', response.answer
				if answerproc is None:
					answerproc = lambda x: x
				retval.append (answerproc (response.answer))
	if len (retval) == 0:
		return None
	return retval


#
# Criterium on Response.Answer: Whether it is non-empty, and is signed
#
# In terms of dnspython, there must be an answer of two components,
#  - one holds the RRset with the requested answers
#  - the other holds the RRSIGs on the answers
#
def rrset_is_nonempty_signed (ans):
	return (len (ans) == 2) and (len (ans [0]) > 0) and (len (ans [1]) > 0)


#
# Test if there are DNSKEY records for the given zone
#
# TODO: Is this the best possible test?  Clients may add them manually,
#       for instance during a rollover procedure.
#
def test_for_signed_dnskey (zone, publisher):
	nss = list_name_servers (zone, publisher)
	rrs = collective_query (zone, rdatatype.DNSKEY, nss, rrset_is_nonempty_signed)
	return combine_individual_outcomes (rrs, publisher)


#
# Add a TTL to "now" to derive an end time (as an integer)
#
def ttl2endtime (ttl):
	if ttl is None:
		return None
	return ttl + int (ceil (time.time ()))


#
# Determine the TTL of the DNSKEY RRset in a zone.
#
def dnskey_ttl (zone, publisher):
	def ttl_of_rrset (ans):
		try:
			return ans [0].ttl
		except:
			syslog.syslog (syslog.LOG_ERR, 'Failed to fetch TTL on DNSKEY for ' + zone + '; assuming 1 day')
			return 86400
	nss = list_name_servers (zone, publisher)
	rrs = collective_query (zone, rdatatype.DNSKEY, nss, ttl_of_rrset)
	return max (rrs)

#
# See if a DS record is published for the given zone
#
def have_ds (zone, publisher=PUBLISHER_PARENTS|PUBLISHER_ALL):
	nss = list_name_servers (zone, publisher)
	rrs = collective_query (zone, rdatatype.DNSKEY, nss, rrset_is_nonempty_signed)
	return combine_individual_outcomes (rrs)

#
# Determine the endtime of the TTL of the DS RRset in a zone.
#
def ds_ttl (zone, publisher=PUBLISHER_PARENTS):
	def ttl_of_rrset (ans):
		try:
			return ans [0].ttl
		except:
			syslog.syslog (syslog.LOG_ERR, 'Failed to fetch TTL on DS for ' + zone + '; assuming 1 day')
			return 86400
	nss = list_name_servers (zone, publisher)
	rrs = collective_query (zone, rdatatype.DS, nss, ttl_of_rrset)
	return max (rrs)


#
# Determine the endtime of the TTL of the DS RRset in a zone.
#
def ds_ttl_endtime (zone, publisher=PUBLISHER_PARENTS):
	return ds_ttl (zone, publisher) + int (ceil (time.time ()))


#
# Determine the negative caching time for the given zone; return that value
# as though it were a published TTL, so as a number of seconds that a negative
# result would be cached.
#
# RFC 2305, Section 5 defines this time from the SOA record; it is the
# minimum of the SOA.MINIMUM field and the SOA TTL.
#
def negative_caching_ttl (zone, publisher):
	def soatime (ans):
		try:
			resp = []
			soattl = ans [0].ttl
			for ans1 in ans [0]:
				soamin = ans1.minimum
				resp.append (min (soattl, soamin))
			return max (resp)
		except:
			# In case of doubt, err on the safe side
			syslog.syslog (syslog.LOG_ERR, 'Failed to fetch negative caching time from SOA for ' + zone + '; assuming 1 day')
			return 86400
	nss = list_name_servers (zone, publisher)
	rrs = collective_query (zone, rdatatype.SOA, nss, soatime)
	if rrs is None or len (rrs) == 0 or None in rrs:
		syslog.syslog (syslog.LOG_ERR, 'Irregularities in negative caching time for ' + zone + '; assuming 1 day')
		nctime = 86400
	else:
		nctime = max (rrs)
	return nctime

