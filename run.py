import os
import argparse

def main():
    """Runs pox controller which points to h1,h2, and h3."""
    ip = '10.0.1.1'
    parser = argparse.ArgumentParser(description='Command line tool for quickly spinning up POX Controller')
    parser.add_argument("-n", type=int, help="number of servers")
    parser.add_argument("-lb", type=str, help="load balancing module")
    args = parser.parse_args()

    servers = ''
    numservers = args.n
    lb_alg = args.lb

    for i in range(0, numservers):
        servers += '10.0.0.{}'.format(i+1)

        if i != numservers-1:
            servers += ','

    command = "sudo python pox.py log.level --DEBUG {lb} --ip={ip} --servers={servers}".format(
        lb=lb_alg,
        ip=ip,
        servers=servers
    )

    print("Running command: {}".format(command))
    os.system(command)


if __name__ == "__main__":
    main()
