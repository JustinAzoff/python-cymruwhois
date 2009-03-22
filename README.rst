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
