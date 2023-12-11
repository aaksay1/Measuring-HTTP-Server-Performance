import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import IP, TCP
import sys
import math
import numpy as np

load_layer("http")
latencies = []

def get_avg():
    return sum(latencies)/len(latencies)

def percentile(q):

    n = len(latencies)
    index = min(int(n * q), n - 1)
    return latencies[index]

def calculate_percentiles():
    percents = []
    latencies.sort()
    percents.append(percentile(0.25))
    percents.append(percentile(0.50))
    percents.append(percentile(0.75))
    percents.append(percentile(0.95))
    percents.append(percentile(0.99))
    return percents


def measure_webserver(input_file, server_ip, server_port):

    processed_file = rdpcap(input_file)
    reqs = []
    responses = []

    for packet in processed_file:

        if(packet.haslayer(IP) and packet.haslayer(TCP)):

            if(packet.haslayer(http.HTTPRequest) and hasattr(packet[IP], 'dst') and packet[IP].dst == server_ip and hasattr(packet[TCP], 'dport') and packet[TCP].dport == int(server_port)):
                reqs.append(packet)
            if(packet.haslayer(http.HTTPResponse)and hasattr(packet[IP], 'src') and packet[IP].src == server_ip and hasattr(packet[TCP], 'sport') and packet[TCP].sport == int(server_port)):
                responses.append(packet)


    for request in reqs:
        response = 0
        for packet in responses:
            if (packet.haslayer(TCP) and hasattr(packet[TCP], 'seq') and hasattr(request[TCP], 'ack') and packet[TCP].seq == request[TCP].ack):
                response = packet
                break

        if response != 0:
            latencies.append(response.time - request.time)

    if(len(latencies) != 0):

        print(f"AVERAGE LATENCY: {get_avg():.5f}")
        print(f"PERCENTILES: {calculate_percentiles()[0]:.5f}, {calculate_percentiles()[1]:.5f}, {calculate_percentiles()[2]:.5f}, {calculate_percentiles()[3]:.5f}, {calculate_percentiles()[4]:.5f}")
        #print(f"KL DIVERGENCE: {kl_div:.5f}")

if __name__ == "__main__":

    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    measure_webserver(input_file, server_ip, server_port)