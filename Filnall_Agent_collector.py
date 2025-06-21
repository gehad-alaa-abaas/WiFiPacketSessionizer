import scapy.all as scapy
import time
import json
from math import inf
import numpy as np
import ast
from tqdm import tqdm

class PacketInfoExtractor:
    def __init__(self, json_file_path='flow_data.json'):
        self.flow_start_times = {}
        self.flow_data = {}
        self.json_file_path = json_file_path
        self.flow_iat_list = []
        self.fwd_iat_list = []
        self.bwd_iat_list = []
        self.packet_length_list = []
        self.idle_iat_list = []
        self.load_flow_data()

    def get_flow_id(self, packet):
        protocol = packet[scapy.IP].proto
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if packet.haslayer(scapy.TCP):
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                sport = packet[scapy.UDP].sport
                dport = packet[scapy.UDP].dport
            elif packet.haslayer(scapy.ICMP):
                sport = 'N/A'
                dport = 'N/A'
            else:
                protocol = packet[scapy.IP].proto
                if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
                    sport = packet.sport
                    dport = packet.dport
                else:
                    sport = 'N/A'
                    dport = 'N/A'

            # flow_id = tuple([ip_src, ip_dst, sport, dport, protocol])
            # return flow_id
            sorted_flow_id = (
            min(ip_src, ip_dst),
            max(ip_src, ip_dst),
            min(sport, dport),
            max(sport, dport),
            protocol)
            string_id = "{}-{}-{}-{}-{}".format(ip_src, ip_dst,sport, dport,protocol)
            return sorted_flow_id,string_id
        else:
            return None
    def initialize_flow(self, packet):
        # self.idle_iat_list = []
        # self.packet_length_list = []
        flow_id, string_id = self.get_flow_id(packet)
        ip_src, ip_dst, sport, dport, protocol = string_id.split('-')
        if flow_id:
            flow_start_time = packet.time
            self.flow_start_times[flow_id] = flow_start_time
            if flow_id not in self.flow_data:

                self.flow_data[flow_id] = {
                    'source_ip': ip_src,'destination_ip': ip_dst,'source_port':sport, 'destination_port': dport,'protocol': protocol,  
                    'time_stamp': flow_start_time,'flow_duration': 0,'total_fwd_packets': 0, 'total_bwd_packets': 0,'total_len_fwd': 0, 'total_len_bwd': 0,
                    'fwd_len_max': 0, 'fwd_len_min': inf, 'fwd_len_mean': 0, 'fwd_len_std': 0,
                    'bwd_len_max': 0, 'bwd_len_min': inf, 'bwd_len_mean': 0, 'bwd_len_std': 0,
                    'flow_bytes_per_s': 0, 'flow_packets_per_s': 0,
                    'flow_iat_mean': 0, 'flow_iat_std': 0, 'flow_iat_max': 0, 'flow_iat_min': 0,
                    'fwd_iat_total': 0, 'fwd_iat_mean': 0, 'fwd_iat_std': 0, 'fwd_iat_max': 0, 'fwd_iat_min': 0,
                    'bwd_iat_total': 0, 'bwd_iat_mean': 0, 'bwd_iat_std': 0, 'bwd_iat_max': 0, 'bwd_iat_min': 0,'fwd_psh_flags': 0, 'bwd_psh_flags': 0,
                    'fwd_urg_flags': 0, 'bwd_urg_flags': 0,
                    'fwd_header_length': 0, 'bwd_header_length': 0,
                    'fwd_packets_per_s': 0, 'bwd_packets_per_s': 0, 
                    'min_packet_length': inf, 'max_packet_length': 0,
                    'packet_length_mean': 0, 'packet_length_std': 0, 'packet_length_variance': 0,
                    'fin_flag_count': 0, 'syn_flag_count': 0, 'rst_flag_count': 0, 'psh_flag_count': 0,
                    'ack_flag_count': 0, 'urg_flag_count': 0, 'cwe_flag_count': 0, 'ece_flag_count': 0,
                    'down_up_ratio': 0, 'avg_packet_size': 0,
                    'avg_fwd_segment_size': 0, 'avg_bwd_segment_size': 0,
                    'fwd_avg_bytes_bulk': 0, 'fwd_avg_packets_bulk': 0, 'fwd_avg_bulk_rate': 0,
                    'bwd_avg_bytes_bulk': 0, 'bwd_avg_packets_bulk': 0, 'bwd_avg_bulk_rate': 0,
                    'subflow_fwd_packets': 0, 'subflow_fwd_bytes': 0, 'subflow_bwd_packets': 0, 'subflow_bwd_bytes': 0,
                    'init_win_bytes_forward': 0, 'init_win_bytes_backward': 0,
                    'act_data_pkt_fwd': 0, 'min_seg_size_forward': 0,
                    'active_mean': 0, 'active_std': 0, 'active_max': 0, 'active_min': 0,
                    'idle_mean': 0, 'idle_std': 0, 'idle_max': 0, 'idle_min': 0,'label': 'normal',
                }
            self.save_flow_data()

    def calculate_mean(self, current_mean, new_value, count):
        if count == 0:
            return new_value
        else:
            return (current_mean * (count - 1) + new_value) / count

    def extract_basic_features(self, packet):
        try:
            flow_id, string_id = self.get_flow_id(packet)
            if flow_id:
                if flow_id not in self.flow_data:
                    self.initialize_flow(packet)

                flow_start_time = self.flow_start_times.get(flow_id, packet.time)
                flow_duration = packet.time - flow_start_time
                self.flow_data[flow_id]['flow_duration'] = flow_duration
                if flow_duration > 0:
                    # Calculate flow_bytes_per_s and flow_packets_per_s
                    fwd_bytes_per_s = self.flow_data[flow_id]['total_len_fwd'] / flow_duration
                    bwd_bytes_per_s = self.flow_data[flow_id]['total_len_bwd'] / flow_duration
                    flow_bytes_per_s = fwd_bytes_per_s + bwd_bytes_per_s

                    fwd_packets_per_s = self.flow_data[flow_id]['total_fwd_packets'] / flow_duration
                    bwd_packets_per_s = self.flow_data[flow_id]['total_bwd_packets'] / flow_duration
                    flow_packets_per_s = fwd_packets_per_s + bwd_packets_per_s

                    self.flow_data[flow_id]['flow_bytes_per_s'] = flow_bytes_per_s
                    self.flow_data[flow_id]['flow_packets_per_s'] = flow_packets_per_s

                    # Calculate fwd_packets_per_s and bwd_packets_per_s
                    if fwd_packets_per_s > 0:  # Avoid division by zero
                        self.flow_data[flow_id]['fwd_packets_per_s'] = fwd_packets_per_s

                    if bwd_packets_per_s > 0:  # Avoid division by zero
                        self.flow_data[flow_id]['bwd_packets_per_s'] = bwd_packets_per_s

                # Feature extraction logic...
                if packet.haslayer(scapy.IP):
                    if packet.haslayer(scapy.TCP):
                    # Update flag counts
                        self.flow_data[flow_id]['fin_flag_count'] += packet[scapy.TCP].flags.FIN
                        self.flow_data[flow_id]['syn_flag_count'] += packet[scapy.TCP].flags.SYN
                        self.flow_data[flow_id]['rst_flag_count'] += packet[scapy.TCP].flags.RST
                        self.flow_data[flow_id]['psh_flag_count'] += packet[scapy.TCP].flags.PSH
                        self.flow_data[flow_id]['ack_flag_count'] += packet[scapy.TCP].flags.ACK
                        self.flow_data[flow_id]['urg_flag_count'] += packet[scapy.TCP].flags.URG
                        self.flow_data[flow_id]['cwe_flag_count'] += packet[scapy.TCP].flags.CWR
                        self.flow_data[flow_id]['ece_flag_count'] += packet[scapy.TCP].flags.ECE

                    packet_source_ip = packet[scapy.IP].src
                    flow_ip_source = self.flow_data[flow_id]['source_ip']
                    direction = 'forward' if packet_source_ip == flow_ip_source else 'backward'
                    if direction == 'forward':
                        self.flow_data[flow_id]['total_fwd_packets'] += 1
                        if hasattr(packet[scapy.IP], 'len') and packet[scapy.IP].len is not None:
                            # Update the total length of forward packets
                            fwd_packet_len = packet[scapy.IP].len
                            self.flow_data[flow_id]['total_len_fwd'] += fwd_packet_len
                            self.flow_data[flow_id]['fwd_len_max'] = max(self.flow_data[flow_id]['fwd_len_max'], fwd_packet_len)
                            self.flow_data[flow_id]['fwd_len_min'] = min(self.flow_data[flow_id]['fwd_len_min'], fwd_packet_len)
                            self.flow_data[flow_id]['fwd_len_mean'] = self.calculate_mean(
                                self.flow_data[flow_id]['fwd_len_mean'],
                                fwd_packet_len,
                                self.flow_data[flow_id]['total_fwd_packets']
                            )
                            self.flow_data[flow_id]['fwd_len_std'] = np.std(
                                [fwd_packet_len, self.flow_data[flow_id]['fwd_len_std']],
                                ddof=1
                            )
                        if len(self.fwd_iat_list) > 0:
                            fwd_iat = packet.time - self.fwd_iat_list[-1]
                            self.flow_data[flow_id]['fwd_iat_total'] += fwd_iat
                            self.flow_data[flow_id]['fwd_iat_mean'] = np.mean(self.fwd_iat_list)
                            self.flow_data[flow_id]['fwd_iat_std'] = np.std(self.fwd_iat_list, ddof=1)
                            self.flow_data[flow_id]['fwd_iat_max'] = np.max(self.fwd_iat_list)
                            self.flow_data[flow_id]['fwd_iat_min'] = np.min(self.fwd_iat_list)
                        self.fwd_iat_list.append(packet.time)
                        if packet.haslayer(scapy.TCP):
                            self.flow_data[flow_id]['fwd_psh_flags'] += packet[scapy.TCP].flags.PSH
                            self.flow_data[flow_id]['fwd_urg_flags'] += packet[scapy.TCP].flags.URG
                            self.flow_data[flow_id]['init_win_bytes_forward'] = packet[scapy.TCP].window
                            self.flow_data[flow_id]['act_data_pkt_fwd'] += packet[scapy.TCP].dataofs * 4
                            self.flow_data[flow_id]['min_seg_size_forward'] = packet[scapy.TCP].options[2][1] if len(packet[scapy.TCP].options) > 2 else 0
                        self.flow_data[flow_id]['fwd_header_length'] += packet[scapy.IP].ihl * 4

                        fwd_segment_size = self.flow_data[flow_id]['fwd_len_mean'] + self.flow_data[flow_id]['fwd_header_length']
                        self.flow_data[flow_id]['avg_fwd_segment_size'] = fwd_segment_size

                        # Calculate 'fwd_avg_bytes_bulk'
                        if self.flow_data[flow_id]['fwd_packets_per_s'] > 0:
                            fwd_avg_bytes_bulk = self.flow_data[flow_id]['total_len_fwd'] / self.flow_data[flow_id]['fwd_packets_per_s']
                            self.flow_data[flow_id]['fwd_avg_bytes_bulk'] = fwd_avg_bytes_bulk

                        # Calculate 'fwd_avg_packets_bulk'
                        if self.flow_data[flow_id]['fwd_iat_total'] > 0:
                            fwd_avg_packets_bulk = self.flow_data[flow_id]['total_fwd_packets'] / (self.flow_data[flow_id]['fwd_iat_total'] * self.flow_data[flow_id]['fwd_packets_per_s'])
                            self.flow_data[flow_id]['fwd_avg_packets_bulk'] = fwd_avg_packets_bulk

                        # Calculate 'fwd_avg_bulk_rate'
                        if fwd_avg_packets_bulk > 0:
                            fwd_avg_bulk_rate = fwd_avg_bytes_bulk / fwd_avg_packets_bulk
                            self.flow_data[flow_id]['fwd_avg_bulk_rate'] = fwd_avg_bulk_rate

                        # Calculate 'subflow_fwd_packets' and 'subflow_fwd_bytes'
                        subflow_fwd_packets = self.flow_data[flow_id]['total_fwd_packets'] - self.flow_data[flow_id]['fwd_psh_flags']
                        subflow_fwd_bytes = self.flow_data[flow_id]['total_len_fwd'] - self.flow_data[flow_id]['fwd_header_length']
                        self.flow_data[flow_id]['subflow_fwd_packets'] = subflow_fwd_packets
                        self.flow_data[flow_id]['subflow_fwd_bytes'] = subflow_fwd_bytes

                    elif direction == 'backward':
                        self.flow_data[flow_id]['total_bwd_packets'] += 1
                        if hasattr(packet[scapy.IP], 'len') and packet[scapy.IP].len is not None:
                            # Update the total length of backward packets
                            bwd_packet_len = packet[scapy.IP].len
                            self.flow_data[flow_id]['total_len_bwd'] += bwd_packet_len
                            self.flow_data[flow_id]['bwd_len_max'] = max(self.flow_data[flow_id]['bwd_len_max'], bwd_packet_len)
                            self.flow_data[flow_id]['bwd_len_min'] = min(self.flow_data[flow_id]['bwd_len_min'], bwd_packet_len)
                            self.flow_data[flow_id]['bwd_len_mean'] = self.calculate_mean(
                                self.flow_data[flow_id]['bwd_len_mean'],
                                bwd_packet_len,
                                self.flow_data[flow_id]['total_bwd_packets']
                            )
                            self.flow_data[flow_id]['bwd_len_std'] = np.std(
                                [bwd_packet_len, self.flow_data[flow_id]['bwd_len_std']],
                                ddof=1
                            )
                        if len(self.bwd_iat_list) > 0:
                            bwd_iat = packet.time - self.bwd_iat_list[-1]
                            self.flow_data[flow_id]['bwd_iat_total'] += bwd_iat
                            self.flow_data[flow_id]['bwd_iat_mean'] = np.mean(self.bwd_iat_list)
                            self.flow_data[flow_id]['bwd_iat_std'] = np.std(self.bwd_iat_list, ddof=1)
                            self.flow_data[flow_id]['bwd_iat_max'] = np.max(self.bwd_iat_list)
                            self.flow_data[flow_id]['bwd_iat_min'] = np.min(self.bwd_iat_list)
                        self.bwd_iat_list.append(packet.time)
                        self.flow_data[flow_id]['bwd_header_length'] += packet[scapy.IP].ihl * 4
                        if packet.haslayer(scapy.TCP):
                            self.flow_data[flow_id]['fwd_psh_flags'] += packet[scapy.TCP].flags.PSH
                            self.flow_data[flow_id]['fwd_urg_flags'] += packet[scapy.TCP].flags.URG
                            self.flow_data[flow_id]['init_win_bytes_backward'] = packet[scapy.TCP].window
                        # _-___________________________________--_______________________________
                        # Additional calculation for backward traffic features
                        self.flow_data[flow_id]['avg_bwd_segment_size'] = self.calculate_mean(
                            self.flow_data[flow_id]['avg_bwd_segment_size'],
                            bwd_packet_len,
                            self.flow_data[flow_id]['total_bwd_packets']
                        )

                        # Calculate 'bwd_avg_bytes_bulk'
                        if self.flow_data[flow_id]['bwd_packets_per_s'] > 0:
                            bwd_avg_bytes_bulk = self.flow_data[flow_id]['total_len_bwd'] / self.flow_data[flow_id]['bwd_packets_per_s']
                            self.flow_data[flow_id]['bwd_avg_bytes_bulk'] = bwd_avg_bytes_bulk

                        # Calculate 'bwd_avg_packets_bulk'
                        if self.flow_data[flow_id]['bwd_iat_total'] > 0:
                            bwd_avg_packets_bulk = self.flow_data[flow_id]['total_bwd_packets'] / (
                                    self.flow_data[flow_id]['bwd_iat_total'] * self.flow_data[flow_id]['bwd_packets_per_s'])
                            self.flow_data[flow_id]['bwd_avg_packets_bulk'] = bwd_avg_packets_bulk

                        # Calculate 'bwd_avg_bulk_rate'
                        if bwd_avg_packets_bulk > 0:
                            bwd_avg_bulk_rate = bwd_avg_bytes_bulk / bwd_avg_packets_bulk
                            self.flow_data[flow_id]['bwd_avg_bulk_rate'] = bwd_avg_bulk_rate

                        # Calculate 'subflow_bwd_packets' and 'subflow_bwd_bytes'
                        subflow_bwd_packets = self.flow_data[flow_id]['total_bwd_packets'] - self.flow_data[flow_id]['bwd_psh_flags']
                        subflow_bwd_bytes = self.flow_data[flow_id]['total_len_bwd'] - self.flow_data[flow_id]['bwd_header_length']
                        self.flow_data[flow_id]['subflow_bwd_packets'] = subflow_bwd_packets
                        self.flow_data[flow_id]['subflow_bwd_bytes'] = subflow_bwd_bytes
                    if len(self.flow_iat_list) > 0:
                        flow_iat = packet.time - self.flow_iat_list[-1]
                        self.flow_iat_list.append(packet.time)
                        self.flow_data[flow_id]['flow_iat_mean'] = np.mean(self.flow_iat_list)
                        self.flow_data[flow_id]['flow_iat_std'] = np.std(self.flow_iat_list, ddof=1)
                        self.flow_data[flow_id]['flow_iat_max'] = np.max(self.flow_iat_list)
                        self.flow_data[flow_id]['flow_iat_min'] = np.min(self.flow_iat_list)

                    # if len(self.flow_iat_list) > 1:
                    
                    if len(self.flow_iat_list) > 1:
                        active_times = np.diff(self.flow_iat_list)
                        self.flow_data[flow_id]['active_mean'] = np.mean(active_times)
                        self.flow_data[flow_id]['active_std'] = np.std(active_times, ddof=1)
                        self.flow_data[flow_id]['active_max'] = np.max(active_times)
                        self.flow_data[flow_id]['active_min'] = np.min(active_times)
                        # idle_time = flow_iat - np.diff(self.flow_iat_list)[-1]
                        idle_time = flow_iat - self.flow_iat_list[-1]
                        
                        self.idle_iat_list.append(idle_time)
                        idle_times = np.diff(self.idle_iat_list)
                        # idle_times = np.diff(self.idle_iat_list)
                        
                        self.flow_data[flow_id]['idle_mean'] = np.mean(idle_times)
                        self.flow_data[flow_id]['idle_std'] = np.std(idle_times, ddof=1)
                        self.flow_data[flow_id]['idle_max'] = np.max(idle_times)
                        self.flow_data[flow_id]['idle_min'] = np.min(idle_times)
                        # print(f"flow_iat: {flow_iat}")
                        # print(f"np.diff(self.flow_iat_list): {np.diff(self.flow_iat_list)}")
                        # print(f"idle_time: {idle_time}")
                        # print(idle_time,idle_times)

                    self.flow_iat_list.append(packet.time)
                    total_fwd_len = self.flow_data[flow_id]['total_len_fwd']
                    total_bwd_len = self.flow_data[flow_id]['total_len_bwd']
                    if total_bwd_len > 0:
                        down_up_ratio = total_fwd_len / total_bwd_len
                        self.flow_data[flow_id]['down_up_ratio'] = down_up_ratio

                    #   else float('inf')
                   
                    if hasattr(packet[scapy.IP], 'len') and packet[scapy.IP].len is not None:
                        packet_len = packet[scapy.IP].len
                        self.packet_length_list.append(packet_len)
                        if len(self.packet_length_list) > 1:
                            self.flow_data[flow_id]['packet_length_mean'] = np.mean(self.packet_length_list)
                            self.flow_data[flow_id]['packet_length_std'] = np.std(self.packet_length_list, ddof=1)
                            self.flow_data[flow_id]['packet_length_variance'] = np.var(self.packet_length_list, ddof=1)
                            self.flow_data[flow_id]['min_packet_length'] = min(self.flow_data[flow_id]['min_packet_length'], packet_len)
                            self.flow_data[flow_id]['max_packet_length'] = max(self.flow_data[flow_id]['max_packet_length'], packet_len)
                        total_packets = self.flow_data[flow_id]['total_fwd_packets'] + self.flow_data[flow_id]['total_bwd_packets']
                        avg_packet_size = (self.flow_data[flow_id]['total_len_fwd'] + self.flow_data[flow_id]['total_len_bwd']) / total_packets if total_packets > 0 else 0
                        self.flow_data[flow_id]['avg_packet_size'] = avg_packet_size
                self.save_flow_data()

            return self.flow_data[flow_id]
        except Exception as e:
            pass
            # print(f"Error extracting features: {e}")

    def save_flow_data(self):
        # Convert tuple keys to strings before saving to JSON
        flow_data_str_keys = {str(key): value for key, value in self.flow_data.items()}
        with open(self.json_file_path, 'w') as json_file:
            json.dump(flow_data_str_keys, json_file)

    def load_flow_data(self):
        try:
            with open(self.json_file_path, 'r') as json_file:
                flow_data_str_keys = json.load(json_file)
                # Convert string keys back to tuples
                self.flow_data = {tuple(ast.literal_eval(key)): value for key, value in flow_data_str_keys.items()}
                for flow_id, data in self.flow_data.items():
                    self.flow_start_times[flow_id] = data.get('time_stamp', 0)  # Use "time_stamp" as the key
        except FileNotFoundError:
            self.flow_data = {}

    def capture_live_traffic(self, interface='eth0', count=0):
        def packet_callback(packet):
            self.extract_basic_features(packet)
            pbar.update(1)

        packets_to_capture = count if count > 0 else float('inf')

        with tqdm(total=packets_to_capture, unit='packet', unit_scale=True, desc='Capturing') as pbar:
            scapy.sniff(prn=packet_callback, store=0, iface=interface, count=count)

# Example usage for live traffic capture:
extractor = PacketInfoExtractor()
extractor.capture_live_traffic(interface='Wi-Fi', count=100000)
