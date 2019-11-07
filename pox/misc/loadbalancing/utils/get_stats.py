import pycurl
from StringIO import StringIO
import argparse
import time
parser = argparse.ArgumentParser(description='Command line tool for curling and getting statistics')
parser.add_argument("-s", type=str, help="address of server")
parser.add_argument("-n", type=int, help="number of times to curl server")
parser.add_argument("-d", type=int, help="delay in milliseconds between curling again")
args = parser.parse_args()

server = args.s
num_of_times = args.n
delay = args.d

server_addr = "http://{}".format(args.s)
#stats = []
for i in range(num_of_times):
    buffer = StringIO()
    c = pycurl.Curl()
    c.setopt(c.URL, server_addr)
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.VERBOSE, True)
    c.perform()


    body = buffer.getvalue()
    #print(body)
    m = {}
    m['total-time'] = c.getinfo(pycurl.TOTAL_TIME)
    m['connect-time'] = c.getinfo(pycurl.CONNECT_TIME)
    m['pretransfer-time'] = c.getinfo(pycurl.PRETRANSFER_TIME)
    m['redirect-time'] = c.getinfo(pycurl.REDIRECT_TIME)
    m['starttransfer-time'] = c.getinfo(pycurl.STARTTRANSFER_TIME)

    c.close()
    print("curl {}".format(i))
    print(m)
    #stats.append(m)
    time.sleep(float(delay)/1000)
#print(stats)
