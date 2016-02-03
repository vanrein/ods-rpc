# A web-based API for OpenDNSSEC

This document describes an implementation of the careful zone life cycle
as shown in the separate document
[ZONE-LIFECYCLE.PDF](ZONE-LIFECYCLE.PDF).

## Design

A zone has a number of flags attached:

* `signing` indicates that the intention exists to sign the zone; set during `sign_approve` and cleared when `assert_unsigned` returns success;
* `signed` is the starting time from which the zone is signed; setup during `assert_signed` and cleared during `sign_stop`;
* `chaining` indicates that the intention exists to maintain a chain from the parent; set during `chain_start` and cleared during `chain_stop`;
* `chained` is the starting time from which the zone is chained from the parent; setup during `assert_chained` and cleared during `chain_stop`;
* `dsttl` is the DS TTL found in parent zone; setup just before the chain is broken in `chain_stop` and cleared during `assert_unsigned`;
* `dnskeyttl` is the DNSKEY TTL found in the signed zone; setup just before stopping DNSSEC during `sign_stop` and cleared during `assert_unsigned`;
* `invalid` describes what is wrong with the zone that blocks its further processing; raised whenever something unexpected happens to the zone and only cleared through operator intervention.

These flags are stored in `/var/opendnssec/webapi/<zonename>.<flagname>` where
the presence of the file indicates `True` and absense signifies `False`.  Some
files are set to a timestamp or TTL value that supports the phases described
below.

These flags cannot be changed arbitrarily; they must occur in the right places
of the management process.  This process is guarded by `ods-webapi`.  A frontend
*portal* can access this API to request changes, and will be told when things
are wrong.  The `ods-webapi` will ensure that everything in OpenDNSSEC is setup
properly for the requested changes to take place.

In extreme conditions, such as something that would invalidate transactional
semantics, the `invalid` flag is raised.  This calls for operator intervention,
and should not normally occur.  In other words, it is a very suitable aspect
of zone validity monitoring.  The flag will cause `ods-webapi` to refuse any
further actions on the zone. 

## Signed Communication

Actions use HTTP POST to the `ods-webapi` in the `application/jose` format,
also known as JSW Compact Serialisation.  This is a base64-ish string,
formed from a JSON message and a so-called JWS *web signature* on it.
These signatures ensure the secure interaction between sender and recipient;
`ods-webapi` does not require encryption because the DNS impact is going to
be public anyway.

The JWS framework can provide a key identity in a `kid` field; this is a hint
for finding the signing key, so this works like a username.  It should be
set to a format such as `portal+key1@frontend.example.com` where the user,
its key and its host are all variables that help towards flexible access.
The `ods-webapi` can limit access to individual functions to any desired
set of such `kid`s.

On a sidenote, it is unclear what web-specifics the JWS framework
provides; as far as the underlying mechanism is concerned, other transport
mechanisms would be just as usable as HTTP; other possible
transports would be SMTP, CoAP, MSRP, SIP, XMPP and many more.  HTTP just
happens to be friendly to the frontend that is currently most popular.

The reason for using JOSE is that this just adds a signature; simple
HMAC signatures based on shared secrets are supported, as well as the more
advanced public key systems.  The transport format is a matter of standard
implementation, and the JSON format that it is going to be signed is defined
below.

During the interaction, a so-called *DNSSEC Request* in JSON format is sent
to the `ods-webapi` using JWS, and a *DNSSEC Response* formulates a reply
on the action.  The DNSSEC Request format welcomes bulk commands, that is
zones are provided as a list.  There is no provision for multiple operations
in one request, as that would confuse the semantics and complicate error
handling.

While signing, a `timestamp` header is added; this is generally a floating
point number of seconds since the start of Jan 1, 1970.  Furthermore, a header
`kid` holds a list of signing key identifiers.  It is possible to sign with
multiple keys, which is useful during migrations, and the verification
process succeeds when only one of these keys verifies properly.  Note that
all the `kid` values must be set before signing commences, as they will be
incorporated into the signature.

When a message has problems with their signature, or their timestamp is
too far off, then the connection will be reset on security grounds.

## JSON format of DNSSEC Requests

A DNSSEC Request is a dictionary with a `command` string and a `zones`
attribute to which it is applied.  For instance,

    {
        "command": "sign_start",
        "zones": [
            "example.com",
            "john.example.org"
        ]
    }

This is a request to execute the command `sign_start`, defined below, on the
zones `example.com` and `john.example.org`.

## JSON format of DNSSEC Responses

A DNSSEC Respsonse is a dictionary with a number of zone lists, where
the list name indicates how processing went.  The `ok` list indicates
those changes that went through fine, the `invalid` list indicates zones
that have their `invalid` flag raised, the `badstate` list indicates zones
that are in an unsuitable state for the requested command, `error`
indicates other errors with the requested zone action.  Any of these lists may
be absent, which is equivalent to an empty list.  All zones listed in the
corresponding DNSSEC Request occur in precisely one list.

    {
        "ok": [
            "example.com"
        ],
        "badstate": [
            "john.example.org"
        ]
    }

## Available Commands

Below are command definitions.

### sign_start

Use `sign_start` to indicate an intention to start signing, although not
approved yet.  The command returns `badstate` if the zone is not free
to be signed.

Precondition: The zone must have no flags set.

Postcondition: Dito.

### sign_approve

Use `sign_approve` to approve a zone that was introduced with `sign_start`.
This initiates background processing by OpenDNSSEC and authoritative
name servers.

Precondition: The zone must have no flags set.  The DNS information is available.

Postcondition: The `signing` flag is set; OpenDNSSEC has the zone setup.

### assert_signed

Use `assert_signed` to ensure that signing has been setup completely.
The command will return `error` until the zone is properly signed.

When at least one signed DNSKEYs is found in all authoritative name servers,
the `signed` flag will be checked.  If it was not set yet, it will be set
(thus storing the timestamp at which it is set).  The `signed` flag file will be
filled with its creation time plus the negative caching TTL; this value must be
passed before this function returns `ok`; until that time, this function returns
`error` to indicate that the assertion cannot be delivered yet.

Note that the negative caching TTL is defined by
[Section 5 of RFC 2308](https://tools.ietf.org/html/rfc2308#section-5)
as the minimum of the zone's SOA TTL and the SOA.MINIMUM field.

Precondition: The `signing` flag is set; OpenDNSSEC has the zone setup; it
appears in all authoritative name servers.

Postcondition: The `signing` and `signed` flags are set; the latter has been
created at least the TTL of TODO ago; OpenDNSSEC has the zone setup and it
appears in all authoritative name servers.

### chain_start

Use `chain_start` to setup the chaining link to parent zones.
This initiaties background processing between OpenDNSSEC and parent zones.

Precondition: The `signing` flag is set; OpenDNSSEC has the zone setup;
it appears in all authoritative name servers.

Postcondition: The `signing` and `chaining` flags are set.

### assert_chained

Use `assert_chained` to ensure that the `DS` link from the parent zone down
to this zone is visible to everyone.  This means that the `DS` records are
published in all the parent's authoritatives and that the applicable TTLs
have expired.  This command returns `error` until this state has been
reached.

Precondition: The `signing` and `chaining` flags are set.

Postcondition: Dito; the zone can now be notified as "signed" to the user.

### chain_stop

Use `chain_stop` to begin breaking down DNSSEC.  This first thing to do is
to bring the chain down, while OpenDNSSEC continues signing for the time
being.  This initiates background activity to remove `DS` records from the
parent zone.

Precondition: The `signing` and `chained` flags are set.  The parent has
the proper `DS` records installed.

Postcondition: The `signing` flag is set, `chained` is cleared.  The parent
does not have the `DS` records installed.

### assert_unchained

Use `assert_unchained` to ensure that nobody sees the `DS` records in the
parent anymore; this means that the parent no longer promotes the
`DS` records for the zone *and* that the TTL on the records has passed.
This returns `error` until this condition has been reached.

Precondition: The `signing` flag is set, `chained` is not.

Postcondition: Dito.  Plus, nobody has reason to require that the zone is signed.

### sign_ignore

Use `sign_ignore` to indicate to OpenDNSSEC that its signing will henceforth
be ignored.  Signing does commence for the time being.

Precondition: The `signing` flag is set.

Postcondition: The `signing` flag is set.

### sign_stop

Use `sign_stop` to order OpenDNSSEC to stop signing.  This may initiate a
background process of cleanup.

Precondition: The `signing` flag is set, `chaining` is not.

Postcondition: The `signing` flag is undefined, the `chaining` flag is cleared.

#### assert_unsigned

Use `assert_unsigned` to assure that a zone is no longer being signed.
The user can now be told that the zone is unsigned, with no traces left,
and that the zone is free to enter another signing cycle, either here or
elsewhere.  (Note that signed transfrers are not supported by `ods-webapi`,
as it involves manual migration of keys anyway.)

Precondition: The `signing` flag is as it was left after `sign_stop`, and `chaining` is cleared.

Postcondition: The `signing` flag is cleared, as is `chaining`.



