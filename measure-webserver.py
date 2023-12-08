import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import IP, TCP
import sys


def func(input_file, server_ip, server_port):
    
    latencies = []

    processed_file = rdpcap(input_file)

    http_requests = []
    for pkt in processed_file:
        if (
            pkt.haslayer(http.HTTPRequest)
            and IP in pkt
            and hasattr(pkt[IP], 'dst') and pkt[IP].dst == server_ip
            and TCP in pkt
            and hasattr(pkt[TCP], 'dport') and pkt[TCP].dport == int(server_port)
        ):
            http_requests.append(pkt)

    http_responses = []
    for pkt in processed_file:
        if (
            pkt.haslayer(http.HTTPResponse)
            and IP in pkt
            and hasattr(pkt[IP], 'src') and pkt[IP].src == server_ip
            and TCP in pkt
            and hasattr(pkt[TCP], 'sport') and pkt[TCP].sport == int(server_port)
        ):
            http_responses.append(pkt)

    for request in http_requests:
        response = None
        for pkt in http_responses:
            if (
                TCP in pkt
                and hasattr(pkt[TCP], 'seq') and hasattr(request[TCP], 'ack')
                and pkt[TCP].seq == request[TCP].ack
            ):
                response = pkt
                break

        if response:
            latency = response.time - request.time
            latencies.append(latency)

    if latencies:
        average_latency = sum(latencies) / len(latencies)
        sorted_latencies = sorted(latencies)
        percentiles = [
            sorted_latencies[int(len(sorted_latencies) * 0.25)],
            sorted_latencies[int(len(sorted_latencies) * 0.50)],
            sorted_latencies[int(len(sorted_latencies) * 0.75)],
            sorted_latencies[int(len(sorted_latencies) * 0.95)],
            sorted_latencies[int(len(sorted_latencies) * 0.99)],
        ]

        print(f"AVERAGE LATENCY: {average_latency:.5f}")
        print(f"PERCENTILES: {percentiles[0]:.5f}, {percentiles[1]:.5f}, {percentiles[2]:.5f}, {percentiles[3]:.5f}, {percentiles[4]:.5f}")

if __name__ == "__main__":

    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    func(input_file, server_ip, server_port)