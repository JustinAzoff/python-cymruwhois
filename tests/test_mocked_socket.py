import cymruwhois
import socket
import errno

class FakeFile:
    def __init__(self, lines):
        self.lines = lines
        self.iter = iter(lines)
        self.written = []
    def write(self, data):
        self.written.append(data)
        return
    def flush(self):
        return
    def readline(self):
        try :
            try:
              return self.iter.next()
            except AttributeError:
              return self.iter.__next__() # for Python 3
        except StopIteration:
            raise socket.error(errno.EAGAIN, 'bleh')
    def read(self, bytes):
        try :
            try:            
              return self.iter.next()
            except AttributeError:
              return self.iter.__next__() # for Python 3
        except StopIteration:
            raise socket.error(errno.EAGAIN, 'bleh')

class FakeSocket:
    def __init__(self):
        pass
    def setblocking(self,x):
        pass

def test_normal():
    l=cymruwhois.Client(memcache_host=None)
    l.socket = FakeSocket()
    l.file = FakeFile([
        '22990   | 169.226.11.11    | 169.226.0.0/16      | US | ALBANYEDU - The University at Albany'
    ])
    l._connected = True

    rec = l.lookup("169.226.11.11")
    assert rec.asn      == '22990'
    assert rec.cc       == 'US'
    assert rec.owner    == 'ALBANYEDU - The University at Albany'


def test_multiple_returned_for_a_single_ip():
    l=cymruwhois.Client(memcache_host=None)
    l.socket = FakeSocket()
    l.file = FakeFile([
        '22990   | 169.226.11.11    | 169.226.0.0/16      | US | ALBANYEDU - The University at Albany',
        '22991   | 169.226.11.11    | 169.226.0.0/16      | US | ALBANYEDU - The University at Albany',
        '15169   | 66.102.1.104     | 66.102.0.0/23       | US | GOOGLE - Google Inc.',
    ])
    l._connected = True

    rec = l.lookup("169.226.11.11")
    assert rec.asn      == '22990'

    rec = l.lookup("66.102.1.104")
    assert rec.asn      == '15169'


def test_multiple_returned_for_a_single_ip_dict():
    l=cymruwhois.Client(memcache_host=None)
    l.socket = FakeSocket()
    l.file = FakeFile([
        '22990   | 169.226.11.11    | 169.226.0.0/16      | US | ALBANYEDU - The University at Albany',
        '22991   | 169.226.11.11    | 169.226.0.0/16      | US | ALBANYEDU - The University at Albany',
        '15169   | 66.102.1.104     | 66.102.0.0/23       | US | GOOGLE - Google Inc.',
    ])
    l._connected = True

    recs = l.lookupmany_dict(['169.226.11.11','66.102.1.104'])
    rec = recs['169.226.11.11']
    assert rec.asn      == '22990'

    rec = recs['66.102.1.104']
    assert rec.asn      == '15169'
