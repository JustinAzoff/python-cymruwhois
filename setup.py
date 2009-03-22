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
    entry_points = {
        'console_scripts': [
            'cymruwhois   = cymruwhois:lookup_stdin',
        ]
    },
)
