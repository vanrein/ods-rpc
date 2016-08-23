# Interaction with parenting

> *Parenting is the name we use for the relation between a zone and its parent
> that should hold its DS records.  We have created scripting to guide this
> process, and wish to link to this from ods-rpc.*

The parenting process currently responds to the OpenDNSSEC `zonelist.xml` file.
When management moves to the `ods-rpc` toolkit, it may be more interesting to
listen in on the `/var/opendnssec/rpc` flag registry, and specifically the
`*.chaining` flag that signals intention to have a zone chained.  When this
flag is set, the DNSKEY records can be setup for the zone's parenting state
diagram; when it is cleared, the DNSKEY records can be removed or the list
made empty.

The DNSKEY RRset to pass through the parenting script should not be provided
from the `ods-rpc` toolkit, because that information would not be updated
when the keys rollover during the zone lifetime.  The interest of `ods-rpc` 
is limited to introducing and removing a zone, without care for its actual
lifetime.

This also means that the `ods-rpc` only cares for the absence and presence
of *some* DS records in the parent, without verifying precisely which ones
they are.  This is a realistic liability if absence of DS records is
validated before introducing them (that is, before setting the `*.chaining`
flag) and when it is either assumed or verified that they are present before
retracting them (by clearing the `*.chaining` flag).

The two processes end up being fairly orthogonal; where parenting is
concerned with the contents of the various DNSKEY or DS records (and
processes anything of current interest), the `ods-rpc` code is interested
in introducing and removing the chain from a parent down to a child zone.

**Changes to parenting code:**

  * DONE - Still use zonelist to know what zones are managed
  * DONE - Look at `*.chaining` flags and introduce zones' DSs when set.
  * DONE - When `*.chaining` and `*.chained` flags are cleared (which happens in unison, so just checking `*.chaining` suffices), remove their DSs from their parents
  * DONE - Permit processing of emty DNSKEY RRsets in parenting code.
  * DONE - Cleanup all administrative files when all files are empty.

**Changes to ods-rpc:**

  * DONE - Verify initial absense of DS records during `start_chaining`.
  * DONE - Wait for presence of DS records during `assert_chained`.
  * ORTHOGONAL - Can we handle a child being introduced to a local parent?
  * ORTHOGONAL - Can we handle a parent being introduced to a local child?
  * FUTURE - Is there something we can do with CDS records?

