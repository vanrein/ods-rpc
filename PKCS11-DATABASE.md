# PKCS #11 as the Zone Database

> *We can rely on PKCS #11 as the store for our zone information.  The format
> of the information stored is detailed below.*

What follows applies chiefly to the direct backend; the KSM-based backend
would cause the Enforcer's rules to be applied.

Note that the direct backend currently relies on PyKCS11, which has a
stringent GPL license.  As a result, the entire software stack is infected
with that same license.  This currently stops us from adding the direct
backend as a mainstream component.

## Key material

**Private keys** are stored with the following information:

  * `CKA_ID` is set to a unique value; when we generate keys using the
    direct backend, we use a BCD-encoded format because this binary field
    is usually printed in hexadecimal.  The value is set to a date and
    time format, with microsecond precision: `YYYYMMDDhhmmssuuuuuu` but
    any other format, including the random strings from `ods-enforcerd`,
    are workable.
  * `CKA_LABEL` is a space-separated list of zone names.  This is where
    we get our information that derives to the `zones.list` input to
    `ods-signerd` when we use the direct backend.  In most roll-outs,
    this field will hold a single zone.  In some roll-outs, this field
    may hold an empty string (but be present nonetheless) to indicate
    that it is part of a pool of pre-generated keys.

A `CKA_LABEL` matching the string representation of the `CKA_ID`
on any of the objects is a warning sign;
it indicates that the `ods-enforcerd` may have been creating objects.
At present, this will result in a fatal error from the backend while
loading information from PKCS #11.  In a future version, we may add
a scan of a `zones.list` and/or the directory with `signconf` files
to establish a relation to such objects, and set a `CKA_LABEL` for them.
After that, the only failure that could remain would be for anything
else that is remaining.  This might be a transitional measure, but it
deserves criticism for replacing the `ods-enforcerd` altogether.

**Public keys** may be suppressed with the `<SkipPublicKey/>` though that is
not possible with ECDSA.  Since ECDSA is the only advised mode of using
the direct backend, there is no support for this option (though that
might change in the future, so don't rely on its absense either).

The identification of a public key is done with the same `CKA_ID` value
as the private key.  In addition, the same `CKA_LABEL` is set.

