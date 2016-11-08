This client still works, but relying on a 3rd party service has downsides for reliability and performance reasons.  I've started a new project called [asnlookup](https://github.com/justinazoff/asnlookup) to allow one to perform lookups locally or to operate a similar service on their own infrastructure.  If autonomy and 160,000 queries/second interests you, check it out.




----------

Perform lookups by ip address and return ASN, Country Code, and Netblock Owner::

    >>> import socket
    >>> ip = socket.gethostbyname("www.google.com")
    >>> from cymruwhois import Client
    >>> c=Client()
    >>> r=c.lookup(ip)
    >>> print r.asn
    15169
    >>> print r.owner
    GOOGLE - Google Inc.


See http://packages.python.org/cymruwhois/ for full documentation.
