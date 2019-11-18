from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController


class SingleSwitchTopo(Topo):
    """Single switch connected to n hosts."""
    def build(self, n=2):
        switch = self.addSwitch('s1')

        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHqost('h%s' % (h + 1))
            self.addLink(host, switch)


def start():
    topo = SingleSwitchTopo(n=6)
    mininet = Mininet(topo)
    mininet.start()
