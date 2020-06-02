#!/usr/bin/env python
# coding: utf8

"""mcscan.py: Scans an ip range for Minecraft multiplayer server."""

__author__   	= "Kevin Gliewe aka KillerGoldFisch"
__copyright__ 	= "Copyright 2016, Kevin Gliewe"
__credits__ 	= ["Kevin Gliewe",]
__license__ 	= "MIT"
__version__ 	= "1.1.0"
__date__ 	    = "2016-01-01"
__maintainer__ 	= "Kevin Gliewe"
__email__	    = "kevingliewe@gmail,com"
__status__ 	    = "Production"

import mcstat, socket, re, struct, sys, threading

IP_RE = re.compile(r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\."+
                   r"([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$")

EXCEPTION_IP_NOT_VALID = "'%(ip)s' in not a valid IP Address"
EXCEPTION_TOO_MANY_IPS = "Too manny ips between '%(ip_from)s' and '%(ip_to)s"

MAX_IPS = 10240

def _print(*args):
    pass
    #print " ".join(str(x) for x in args)


def _genSock1():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    return s

def _genSock2():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    return s

sockets = [
    _genSock1,
#    _genSock2
]

def _update_progress(progress, l=60):
    l_1 = int(progress*l)
    l_2 = l - l_1
    p = 100 *progress
    sys.stdout.write('\r[{0}{1}] {2:3.1f}%'.format('#'*l_1," "*l_2 , p))
    sys.stdout.flush()

def _parseIp(ip):
    ip_re = IP_RE.match(ip)

    if ip_re is None:
        raise Exception(EXCEPTION_IP_NOT_VALID%{"ip": ip})
    return [int(i) for i in ip_re.groups()]

def int_from_bytes(b3, b2, b1, b0):
    return (((((b3 << 8) + b2) << 8) + b1) << 8) + b0

def _collectIps(ip_from, ip_to):
    ips = []
    fr = int_from_bytes(*ip_from)
    to = int_from_bytes(*ip_to)

    #print "fr: ",fr
    #print "to: ",to

    if to - fr > MAX_IPS:
        raise Exception(EXCEPTION_TOO_MANY_IPS%{
                "ip_from":str(ip_from),
                "ip_to":str(ip_to)})

    for i in range(fr, to+1):
        ips.append([ ord(c) for c in struct.pack("!I", i) ])

    return ips

def _scanIp(ip, port=25565):
    ip = ".".join(str(x) for x in ip)
    sock = None
    status = None

    _print("Start scanning ip '%s:%d'"%(ip, port))

    for s in sockets:
        s = s()

        _print("\tTesting socket ", s)
        result = s.connect_ex((ip, port))
        if result == 0:
            sock = s
        _print("\t\t", "success" if result==0 else "fail")
        s.close()
        if sock is None:
            continue

    if sock is not None:
        _print("\tTesting status")
        try:
            status = mcstat.getStat(ip, port, 0.5)
            _print("\t\tsuccess")
        except Exception, ex:
            _print("\t\tfail")
            status = ex

    return ip, sock is not None, socket.getfqdn(ip) if sock is not None else None, status




def scan(ip_from, ip_to, progress=False, worker=8):
    from multiprocessing import Process, Lock, Manager, cpu_count
    import time

    if worker <= 0:
        try:
            worker=cpu_count() * 4
        except:
            worker = 8

    t_start = time.time()

    manager = Manager()

    ip_from = _parseIp(ip_from)
    ip_to = _parseIp(ip_to)

    ips = manager.list(_collectIps(ip_from, ip_to))
    ips_len = float(len(ips))

    if ips_len == 0:
        return []

    ret = manager.list()

    l_ips = Lock()

    def _worker(id = 0):#, l_ips=Lock(), ips = [], ret= []):
        ip = None
        while(True):
            try:
                time.sleep(0.005)
                l_ips.acquire()
                ip = ips.pop() if len(ips) > 0 else None
                l_ips.release()
                if ip is None: break
                r = _scanIp(ip)
                if r[1]:
                    ret.append(r)
            except Exception, ex:
                print "Worker %d Exception:%s"%(id, str(ex))

    processes = []

    for i in range(worker):
        #p = Process(target=_worker, args=(i+1,))#, l_ips, ips, ret))
        #p.start()
        t=threading.Thread(target=_worker, args=(i+1,))
        t.start()
        processes.append(t)

    while(sum([1 for p in processes if p.is_alive()]) > 0):
        time.sleep(0.1)
        if progress:
            _update_progress((ips_len-len(ips))/ips_len)

    if progress:
        print "\rTime=%s"%(time.time()-t_start)
    return ret

def main():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Scans an ip range for Minecraft multiplayer server")
    parser.add_argument("-p", "--progress",
                    action="store_false", dest="progress", default=True,
                    help="don't print progress to stdout")
    parser.add_argument("start", help="target hostname")
    parser.add_argument("stop", help="target hostname")
    parser.add_argument('format', nargs='?', choices=('text', 'html', 'markdown'), default='text')

    options = parser.parse_args()

    print options

    for entry in scan(options.start, options.stop, options.progress):

        if options.format == 'html':
            def kv(key, val):
                return '<tr><th align="right">%0s</th><td>%1s</td></tr>'%(
                    str(key).strip(), 
                    str(val).strip()
                )

            print '<h2>' + entry[0] + '</h2>'
            print '<div><table>'

            print kv('IP', entry[0])
            if entry[0]!=entry[2]:
                print kv("Domain", entry[2])

            for x in str(entry[3]).split("\n"):
                y = x.split(':')

                if len(y) >= 2:
                    print kv(y[0], ':'.join(y[1:]))
                else:
                    print kv('', y[0])

            print '</table></div><br/>'

        elif options.format == 'markdown':
            pass
        else:
            print "-"*80
            print "ip: ",entry[0]
            if entry[0]!=entry[2]:
                print "domain: ",entry[2]
            print "status:"
            print "\n".join(["\t"+x for x in str(entry[3]).split("\n")])

if __name__=="__main__":
    main()