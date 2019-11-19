from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController


class SingleSwitchTopo(Topo):
    """Single switch connected to n hosts."""
    def build(self, n=2):
        switch = self.addSwitch('s1')

        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)


def start():
    """
    Builds default mininet topology with N nodes. N-1 of those nodes are servers, while 1 is a client, which
    we will use as a traffic generator to test our load balancing algorithms.
    """
    size = 4
    topo = SingleSwitchTopo(n=size)

    mininet = Mininet(topo)
    mininet.start()

    command = "python -m SimpleHTTPServer 80 &"

    print("Spinning up Default Loadbalancing Test Topology with {} total nodes and {} servers.".format(size, size-1))

    for i in range(0, size-1):
        h = mininet.hosts[i]
        h.cmd(command)
        print("{} now running SimpleHTTPServer".format(h))

    CLI(mininet)


if __name__ == '__main__':
    start()
