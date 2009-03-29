Command-line Interface
======================
The cymruwhois utility program lets you do lookups from the command line or
shell scripts.

Lookups can be done from stdin or from files::

    justin@dell ~ % cat /tmp/ips | cymruwhois 
    15169    66.102.1.104    66.102.0.0/23      US GOOGLE - Google Inc.
    22990    169.226.1.110   169.226.0.0/16     US ALBANYEDU - The University at Albany
    12306    82.98.86.176    82.98.64.0/18      DE PLUSLINE Plus.Line AG IP-Services

    justin@dell ~ % cymruwhois /tmp/ips
    15169    66.102.1.104    66.102.0.0/23      US GOOGLE - Google Inc.
    22990    169.226.1.110   169.226.0.0/16     US ALBANYEDU - The University at Albany
    12306    82.98.86.176    82.98.64.0/18      DE PLUSLINE Plus.Line AG IP-Services


The formatting and contents of the output can be controlled with the -f and -d options::

    justin@dell ~ % cymruwhois /tmp/ips -f asn,cc
    15169    US
    22990    US
    12306    DE

    justin@dell ~ % cymruwhois /tmp/ips -f asn,cc -d,
    15169,US
    22990,US
    12306,DE
