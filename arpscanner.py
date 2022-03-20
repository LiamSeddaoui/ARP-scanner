from scapy.all import ARP, Ether, srp
import argparse


parser = argparse.ArgumentParser(
    description="Simple Scanner ARP")
parser.add_argument("-cidr", dest="CIDR",
                    help="Indicate CIDR (/24)", required=False)
# parser.add_argument("-das", dest="pathlog", help="Path of directory auto-save results", required=False)
args = parser.parse_args()


network = "192.168.1.1" + str(args.CIDR)

arp = ARP(pdst=network)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether / arp

result = srp(packet, timeout=3, verbose=0)[0]


clients = []

for sent, received in result:

    clients.append({'ip': received.psrc, 'mac': received.hwsrc})


print("Available devices in the network:")
print("IP" + " " * 18 + "MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
