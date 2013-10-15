from setuptools import setup
from glob import glob

setup(name="cymruwhois",
    version="1.4",
    description="Client for the whois.cymru.com service",
    long_description="""
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

    """,

    url="http://packages.python.org/cymruwhois/",
    download_url="http://github.com/JustinAzoff/python-cymruwhois/tree/master",
    license='MIT',
    classifiers=[
        "Topic :: System :: Networking",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords='ASN',
    author="Justin Azoff",
    author_email="JAzoff@uamail.albany.edu",
    py_modules = ["cymruwhois"], 
    extras_require = {
        'CACHE':  ["python-memcached"],
        'docs' : ['sphinx'],
        'tests' : ['nose'],
    },
    entry_points = {
        'console_scripts': [
            'cymruwhois   = cymruwhois:lookup_stdin',
        ]
    },
    setup_requires=[
    ],
    test_suite='nose.collector',
)
