import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import IP, TCP
import sys
import math

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

def measured_distribution():
    min_latency = min(latencies)
    max_latency = max(latencies)
    bucket_size = (max_latency - min_latency) / 10

    bucket_counts = [0] * 10
    for latency in latencies:
        bucket_index = min(int((latency - min_latency) / bucket_size), 9)
        bucket_counts[bucket_index] += 1

    total_measurements = len(latencies)
    measured_distribution = [count / total_measurements for count in bucket_counts]
    print(measured_distribution)
    return measured_distribution



def exponential_model_distribution():
    mean_response_time = get_avg()
    rate_parameter = 1.0 / float(mean_response_time)

    min_latency = min(latencies)
    max_latency = max(latencies)
    bucket_size = (max_latency - min_latency) / 10

    bucket_boundaries = [i * bucket_size for i in range(11)]
    exponential_distribution = []

    for i in range(9):
        lower_boundary = bucket_boundaries[i] * (1.0 / float(bucket_size))
        upper_boundary = bucket_boundaries[i + 1] * (1.0 / float(bucket_size))

        cdf_lower_boundary = 1 - math.exp(-rate_parameter * lower_boundary)
        cdf_upper_boundary = 1 - math.exp(-rate_parameter * upper_boundary)

        probability_mass = cdf_upper_boundary - cdf_lower_boundary
        exponential_distribution.append(probability_mass)

    # Last bucket calculation
    last_upper_boundary = bucket_boundaries[9] * (1.0 / float(bucket_size))
    cdf_last_upper_boundary = 1 - math.exp(-rate_parameter * last_upper_boundary)
    probability_mass_last_bucket = 1 - cdf_last_upper_boundary
    exponential_distribution.append(probability_mass_last_bucket)

    return exponential_distribution



def kl_divergence(dist1, dist2):
    if len(dist1) != len(dist2):
        raise ValueError("WRONG")
    
    kl_sum = 0.0
    for i in range(len(dist1)):

        if((dist1[i]==0) or (dist2[i] == 0)):
            continue

        kl_sum = kl_sum +(dist1[i] * math.log2(dist1[i]/dist2[i]))

    return kl_sum

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
        kl_div =  kl_divergence(exponential_model_distribution(), measured_distribution())

        print(f"AVERAGE LATENCY: {get_avg():.5f}")
        print(f"PERCENTILES: {calculate_percentiles()[0]:.5f}, {calculate_percentiles()[1]:.5f}, {calculate_percentiles()[2]:.5f}, {calculate_percentiles()[3]:.5f}, {calculate_percentiles()[4]:.5f}")
        print(f"KL DIVERGENCE: {kl_div:.5f}")
if __name__ == "__main__":

    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    measure_webserver(input_file, server_ip, server_port)