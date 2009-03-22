from setuptools import setup
from glob import glob

setup(name="cymruwhois",
    version="1.0",
    author="Justin Azoff",
    author_email="JAzoff@uamail.albany.edu",
    py_modules = ["cymruwhois"], 
    extras_require = {
        'CACHE':  ["python-memcached"],
    },
    dependency_links = ['ftp://ftp.tummy.com/pub/python-memcached/python-memcached-1.40.tar.gz'],
    entry_points = {
        'console_scripts': [
            'cymruwhois   = cymruwhois:lookup_stdin',
        ]
    },
)
