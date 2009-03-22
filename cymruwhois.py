#!/usr/bin/env python
import socket
import errno

try :
    import memcache
    HAVE_MEMCACHE = True
except ImportError:
    HAVE_MEMCACHE = False

def iterwindow(l, slice=50):
    """Generate sublists from an iterator
    >>> list(iterwindow(iter(range(10)),11))
    [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]]
    >>> list(iterwindow(iter(range(10)),9))
    [[0, 1, 2, 3, 4, 5, 6, 7, 8], [9]]
    >>> list(iterwindow(iter(range(10)),5))
    [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]]
    >>> list(iterwindow(iter(range(10)),3))
    [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
    >>> list(iterwindow(iter(range(10)),1))
    [[0], [1], [2], [3], [4], [5], [6], [7], [8], [9]]
    """

    assert(slice > 0)
    a=[]

    for x in l:
        if len(a) >= slice :
            yield a
            a=[]
        a.append(x)

    if a:
        yield a


class record:
    def __init__(self, asn, ip, prefix, cc, owner):

        def fix(x):
            x = x.strip()
            if x == "NA":
                return None
            return str(x.decode('ascii','ignore'))

        self.asn    = fix(asn)
        self.ip     = fix(ip)
        self.prefix = fix(prefix)
        self.cc     = fix(cc)
        self.owner  = fix(owner)

    def __str__(self):
        return "%-10s %-16s %-16s %s '%s'" % (self.asn, self.ip, self.prefix, self.cc, self.owner)
    def __repr__(self):
        return "<%s instance: %s|%s|%s|%s|%s>" % (self.__class__, self.asn, self.ip, self.prefix, self.cc, self.owner)

class Client:
    """Python interface to whois.cymru.com

    **Usage**

    >>> import socket
    >>> ip = socket.gethostbyname("www.google.com")
    >>> from cymruwhois import Client
    >>> c=Client()
    >>> r=c.lookup(ip)
    >>> print r.asn
    15169
    >>> print r.owner
    GOOGLE - Google Inc.
    >>> 
    >>> ip_ms = socket.gethostbyname("www.microsoft.com")
    >>> for r in c.lookupmany([ip, ip_ms]):
    ...     print r.owner
    GOOGLE - Google Inc.
    MICROSOFT-CORP---MSN-AS-BLOCK - Microsoft Corp
    """
    KEY_FMT = "cymruwhois:ip:%s"

    def __init__(self, host="whois.cymru.com", port=43, memcache_host='localhost:11211'):
        self.host=host
        self.port=port
        self._connected=False
        self.c = None
        if HAVE_MEMCACHE and memcache_host:
            self.c = memcache.Client([memcache_host])

    def _connect(self):
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.settimeout(5.0)
        self.socket.connect((self.host,self.port))
        self.socket.settimeout(1.0)
        self.file = self.socket.makefile()
    def _sendline(self, line):
        self.file.write(line + "\r\n")
        self.file.flush()
    def _readline(self):
        return self.file.readline()
        
    def _disconnect(self):
        self.file.close()
        self.socket.close()

    def read_and_discard(self):
        self.socket.setblocking(0)
        try :
            try :
                self.file.read(1024)
            except socket.error, e:
                if e.args[0]!=errno.EAGAIN:
                    raise
        finally:
            self.socket.setblocking(1)

    def _begin(self):
        """Explicitly connect and send BEGIN to start the lookup process"""
        self._connect()
        self._sendline("BEGIN")
        self._readline() #discard the message "Bulk mode; one IP per line. [2005-08-02 18:54:55 GMT]"
        self._sendline("PREFIX")
        self._sendline("COUNTRYCODE")
        self._sendline("NOTRUNC")
        self._connected=True

    def disconnect(self):
        """Explicitly send END to stop the lookup process and disconnect"""
        if not self._connected: return

        self._sendline("END")
        self._disconnect()
        self._connected=False

    def get_cached(self, ips):
        if not self.c:
            return {}
        keys = [self.KEY_FMT % ip for ip in ips]
        vals = self.c.get_multi(keys)
        #convert cymruwhois:ip:1.2.3.4 into just 1.2.3.4
        return dict((k.split(":")[-1], v) for k,v in vals.items())

    def cache(self, r):
        if not self.c:
            return
        self.c.set(self.KEY_FMT % r.ip, r, 60*60*6)

    def lookup(self, ip):
        """Look up a single address.  This function should not be called in 
        loop, instead call lookupmany"""
        return list(self.lookupmany([ip]))[0]
    
    def lookupmany(self, ips):
        """Look up many ip addresses"""
        ips = [str(ip).strip() for ip in ips]

        for batch in iterwindow(ips, 100):
            cached = self.get_cached(batch)
            not_cached = [ip for ip in batch if not cached.get(ip)]
            #print "cached:%d not_cached:%d" % (len(cached), len(not_cached))
            if not_cached:
                for rec in self._lookupmany_raw(not_cached):
                    cached[rec.ip] = rec
            for ip in batch:
                if ip in cached:
                    yield cached[ip]

    def lookupmany_dict(self, ips):
        """Look up many ip addresses, returning a dictionary of ip -> record"""
        ips = set(ips)
        return dict((r.ip, r) for r in self.lookupmany(ips))
                
    def _lookupmany_raw(self, ips):
        """Do a look up for some ips"""

        if not self._connected:
            self._begin()
        ips = set(ips)
        for ip in ips:
            self._sendline(ip)

        need = len(ips)
        last = None
        while need:
            result=self._readline()
            if 'Error: no ASN or IP match on line' in result:
                need -=1
                continue
            parts=result.split("|")
            r=record(*parts)

            #check for multiple records being returned for a single IP
            #in this case, just skip any extra records
            if last and r.ip == last.ip:
                continue

            self.cache(r)
            yield r
            last = r
            need -=1

        #skip any trailing records that might have been caused by multiple records for the last ip
        self.read_and_discard()
            

#backwards compatibility
lookerupper = Client 

def lookup_stdin():
    from optparse import OptionParser
    import fileinput
    parser = OptionParser(usage = "usage: %prog [options] [files]")
    parser.add_option("-d", "--delim",  dest="delim", action="store", default=None,
        help="delimiter to use instead of justified")
    parser.add_option("-f", "--fields", dest="fields", action="append",
        help="comma separated fields to include (asn,ip,prefix,cc,owner)")

    if HAVE_MEMCACHE:
        parser.add_option("-c", "--cache", dest="cache", action="store", default="localhost:11211",
            help="memcache server (default localhost)")
        parser.add_option("-n", "--no-cache", dest="cache", action="store_false",
            help="don't use memcached")
    else:
        memcache_host = None

    (options, args) = parser.parse_args()

    #fix the fields: convert ['a,b','c'] into ['a','b','c'] if needed
    fields = []
    if options.fields:
        for f in options.fields:
            fields.extend(f.split(","))
    else:
        fields = 'asn ip prefix cc owner'.split()

    #generate the format string
    fieldwidths = {
        'asn': 8,
        'ip': 15,
        'prefix': 18,
        'cc':   2,
        'owner': 0,
    }
    if options.delim:
        format = options.delim.join("%%(%s)s" % f for f in fields)
    else:
        format = ' '.join("%%(%s)-%ds" % (f, fieldwidths[f]) for f in fields)

    #setup the memcache option

    if HAVE_MEMCACHE:
        memcache_host = options.cache
        if memcache_host and ':' not in memcache_host:
            memcache_host += ":11211"

    c=Client(memcache_host=memcache_host)
    ips = []

    for line in fileinput.input(args):
        ip=line.strip()
        ips.append(ip)
    for r in c.lookupmany(ips):
        print format % r.__dict__

if __name__ == "__main__":
    lookup_stdin()
