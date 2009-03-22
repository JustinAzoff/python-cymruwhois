.. cymruwhois documentation master file, created by
   sphinx-quickstart on Sun Mar 22 00:26:37 2009.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to cymruwhois's documentation!
======================================

Contents:

.. toctree::
   :maxdepth: 2

.. warning::
    Do not call the Client.lookup function inside of a loop, the performance
    will be terrible.  Instead, call lookupmany or lookupmany_dict


Cymruwhois
----------

.. autoclass:: cymruwhois.Client
   :members: lookup,lookupmany,lookupmany_dict
   :undoc-members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`

