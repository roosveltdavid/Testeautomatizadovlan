import click
from scapy.all import Ether, Dot1Q, IP, TCP, sendp
from tqdm import tqdm

class VlanPacketGenerator:
    def __init__(self, src_mac, dst_mac, vlan_id, src_ip, dst_ip, dst_port):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.vlan_id = vlan_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def generate_packet(self):
        return Ether(src=self.src_mac, dst=self.dst_mac)/Dot1Q(vlan=self.vlan_id)/IP(src=self.src_ip, dst=self.dst_ip)/TCP(dport=self.dst_port)

def validate_mac_address(address):
    if len(address.split(":")) != 6:
        raise ValueError("Endereço MAC inválido: {}".format(address))

def validate_ip_address(address):
    if len(address.split(".")) != 4:
        raise ValueError("Endereço IP inválido: {}".format(address))

def get_vlan_ids():
    vlan_range = input("Informe o range de VLANs (ex: 10-20): ")
    start, end = map(int, vlan_range.split("-"))
    return list(range(start, end+1))

def get_interface():
    return input("Informe o nome da interface de rede a ser utilizada (ex: eth0): ")

def get_packet_count():
    return int(input("Informe a quantidade de pacotes a serem enviados (ex: 1000): "))

def get_src_mac():
    src_mac = input("Informe o endereço MAC de origem (ex: 00:11:22:33:44:55): ")
    validate_mac_address(src_mac)
    return src_mac

def get_dst_mac():
    dst_mac = input("Informe o endereço MAC de destino (ex: 00:11:22:33:44:66 ): ")
    validate_mac_address(dst_mac)
    return dst_mac

def get_src_ip():
    src_ip = input("Informe o endereço IP de origem (ex: 192.0.2.1 ): ")
    validate_ip_address(src_ip)
    return src_ip

def get_dst_ip():
    dst_ip = input("Informe o endereço IP de destino (ex: 192.0.2.2): ")
    validate_ip_address(dst_ip)
    return dst_ip

def get_dst_port():
    return int(input("Informe um número de porta aleatório de destino (1-65535): "))

def send_vlan_packets():
    vlan_ids = get_vlan_ids()
    iface = get_interface()
    count = get_packet_count()
    src_mac = get_src_mac()
    dst_mac = get_dst_mac()
    src_ip = get_src_ip()
    dst_ip = get_dst_ip()
    dst_port = get_dst_port()

    generators = [VlanPacketGenerator(src_mac, dst_mac, vlan_id, src_ip, dst_ip, dst_port) for vlan_id in vlan_ids]
    progress_bar = tqdm(total=count*len(generators), unit='pkts')
    for i in range(count):
        for generator in generators:
            pkt = generator.generate_packet()
            sendp(pkt, iface=iface, verbose=0)
            progress_bar.update(1)
    progress_bar.close()


if __name__ == "__main__":
    send_vlan_packets()
