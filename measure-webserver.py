from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import IP, TCP
import sys

def func(input_file, server_ip, server_port):

    latencies = []

    processed_file = rdpcap(input_file)
    http_requests = [pkt for pkt in processed_file if pkt.haslayer(http.HTTPRequest)
                    and pkt[IP].dst == server_ip
                    and pkt[TCP].dport == int(server_port)]
    
    http_responses = [pkt for pkt in processed_file if pkt.haslayer(http.HTTPResponse)
                    and pkt[IP].src == server_ip
                    and pkt[TCP].sport == int(server_port)]
    
    for request in http_requests:
        response = next((pkt for pkt in http_responses if pkt[TCP].seq == request[TCP].ack), None)

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
    
    print(f"AVERAGE LATENCY: {average_latency:.5f} seconds")
    print(f"PERCENTILES: {percentiles[0]:.5f}, {percentiles[1]:.5f}, {percentiles[2]:.5f}, {percentiles[3]:.5f}, {percentiles[4]:.5f}")

if __name__ == "__main__":

    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    func(input_file, server_ip, server_port)