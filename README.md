# Network Traffic Feature Extractor

This repository provides a Python tool for live network traffic capture and feature extraction using the Wi-Fi adapter. It collects detailed attributes from each packet and aggregates them into flow/session records, saving the results to a JSON file for further analysis or machine learning tasks.

## Features
- Captures live traffic from a specified network interface (e.g., Wi-Fi)
- Extracts and aggregates over 70+ flow/session-level attributes per network flow
- Supports TCP, UDP, and ICMP protocols
- Saves all session data to a JSON file for later use
- Progress bar for live capture using `tqdm`

## Main Attributes Collected (per flow/session)
- source_ip, destination_ip, source_port, destination_port, protocol
- time_stamp, flow_duration
- total_fwd_packets, total_bwd_packets, total_len_fwd, total_len_bwd
- fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std
- bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std
- flow_bytes_per_s, flow_packets_per_s
- flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min
- fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min
- bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min
- fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags
- fwd_header_length, bwd_header_length
- fwd_packets_per_s, bwd_packets_per_s
- min_packet_length, max_packet_length, packet_length_mean, packet_length_std, packet_length_variance
- fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count, urg_flag_count, cwe_flag_count, ece_flag_count
- down_up_ratio, avg_packet_size
- avg_fwd_segment_size, avg_bwd_segment_size
- fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate
- bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate
- subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets, subflow_bwd_bytes
- init_win_bytes_forward, init_win_bytes_backward
- act_data_pkt_fwd, min_seg_size_forward
- active_mean, active_std, active_max, active_min
- idle_mean, idle_std, idle_max, idle_min
- label (default: 'normal')

**Total attributes per session:** 70+

## Usage
1. Install dependencies:
   - `pip install scapy tqdm numpy`
2. Run the script:
   ```bash
   python Filnall_Agent_collector.py
   ```
   - By default, it captures 100,000 packets from the `Wi-Fi` interface.
   - You can change the interface and packet count in the example usage at the bottom of the script.
3. The session/flow data will be saved to `flow_data.json` in the working directory.

## Customization
- Change the network interface by modifying the `interface` parameter in `capture_live_traffic()`.
- Adjust the number of packets to capture with the `count` parameter.
- Extend or modify the feature extraction logic in the `extract_basic_features` method.

## Example
```python
extractor = PacketInfoExtractor()
extractor.capture_live_traffic(interface='Wi-Fi', count=100000)
```

