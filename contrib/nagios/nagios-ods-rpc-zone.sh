#!/bin/bash
#
# Nagios check for the zone, to ensure it is not flagged .invalid
# The zone is expected in $1
#
# From: Rick van Rein <rick@openfortress.nl>

RPCDIR="/var/opendnssec/rpc"

ZONE="$1"

INVALID=
HACKS=
TEXT=

datestamp() {
	date -d "@$1" +'%Y-%m-%d %H:%M'
}

if [ -r "$RPCDIR/$ZONE.invalid" ]
then
	GONEAWRY=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.invalid"))
	CONTENTS=$(cat "$RPCDIR/$ZONE.invalid")
	INVALID="Invalid since $GONEAWRY: $CONTENTS"
fi

if [ -r "$RPCDIR/$ZONE.waiveds" ]
then
	GONEAWRY=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.waiveds"))
	HACKS="Flag .waiveds since $GONEAWRY"
fi

if [ -r "$RPCDIR/$ZONE.signing" ]
then
	if [ -r "$RPCDIR/$ZONE.signed" ]
	then
		SIGNED=$(datestamp $(cat "$RPCDIR/$ZONE.signed"))
		TEXT="Signed from $SIGNED"
		if [ -r "$RPCDIR/$ZONE.chaining" ]
		then
			if [ -r "$RPCDIR/$ZONE.chained" ]
			then
				CHAINED=$(datestamp $(cat "$RPCDIR/$ZONE.chained"))
				TEXT="$TEXT, Chained from $CHAINED"
			else
				CHAINING=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.chaining"))
				TEXT="$TEXT, Chaining since $CHAINING"
			fi
		fi
	else
		SIGNING=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.signing"))
		TEXT="Signing since $SIGNING"
	fi
else
	TEXT="Not signed"
fi


if [ -r "$RPCDIR/$ZONE.dsttl" ]
then
	if [ -r "$RPCDIR/$ZONE.dnskeyttl" ]
	then
		DNSKEYTTLSTART=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.dnskeyttl"))
		TEXT="$TEXT, Unchained, Unsigning since $DNSKEYTTLSTART"
	else
		DSTTLSTART=$(datestamp $(stat --format %Y "$RPCDIR/$ZONE.dsttl"))
		TEXT="$TEXT, Unchaining since $DSTTLSTART"
	fi
# else: Keep $TEXT as is
fi


#DEBUG# echo TEXT=$TEXT
#DEBUG# echo HACKS=$HACKS
#DEBUG# echo INVALID=$INVALID


if [ -n "$INVALID" ]
then
	#CHOICE# echo "CRITICAL- $ZONE requires intervention: $INVALID"
	#CHOICE# exit 2
	echo "WARNING- ${ZONE:-What Zone?} needs help -- $INVALID"
	exit 1
elif [ -n "$HACKS" ]
then
	echo "WARNING- ${ZONE:-What Zone?} high on hacks -- $HACKS"
	exit 1
else
	echo "OK- ${ZONE:-What Zone?} -- $TEXT"
	exit 0
fi

