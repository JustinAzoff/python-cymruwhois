import cymruwhois
import socket

def test_common():
    l=cymruwhois.Client()
    places = [
        ['www.google.com',    'google'],
        ['www.microsoft.com', 'microsoft'],
        ['www.apple.com',     'apple'],
        ['www.albany.edu',    'albany'],
    ]

    for hostname, owner in places:
        yield common_case, l, hostname, owner

def common_case(client, hostname, owner):
    ip = socket.gethostbyname(hostname)
    r=client.lookup(ip)
    print owner, r.owner.lower()
    assert owner in r.owner.lower()
