import cymruwhois
import socket

def test_common():
    l=cymruwhois.Client()
    places = [
        ['www.google.com',    'google'],
        ['www.yahoo.com',     'yahoo'],
        ['www.albany.edu',    'albany'],
    ]

    for hostname, owner in places:
        yield common_case, l, hostname, owner

def test_asn():
    l=cymruwhois.Client()
    record = l.lookup("AS15169")
    assert 'google' in record.owner.lower()

def common_case(client, hostname, owner):
    ip = socket.gethostbyname(hostname)
    r=client.lookup(ip)
    print(owner, r.owner.lower())
    assert owner in r.owner.lower()
