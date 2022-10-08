import numpy as np
import pyshark

# Get the capture

filename = "traces/bild.de.pcapng"

cap = pyshark.FileCapture(filename)

# Get the DNS query for the target host

cap_dns = pyshark.FileCapture(filename, display_filter='dns')

# print("what is the target host?\n Input below:\n" )

# host = input()

host = 'bild.de'
cap = cap_dns
cap.load_packets()

num_packets = len(cap)
print(len(cap))

for i in range(num_packets):
    if 'DNS' in cap[i]:
        if (cap[i].dns.qry_name==host or cap[i].dns.qry_name=='www.'+host) and cap[i].dns.flags_response == '0':

            print(cap[i])
            dns_id = cap[i].dns.id
            src_ip = cap[i].ip.src_host
            current_index = i
            print(src_ip)        
            break

for i in range(current_index, num_packets):
    if 'DNS' in cap[i]:
        if cap[i].dns.id == dns_id and cap[i].dns.flags_response == '1':

            target_ip = cap[i].dns.a #NOTE: - iterate throught multiple responses.
            print(cap[i].dns.field_names)
            # cap[i].dns.field_names outputs: ['id', 'flags', 'flags_response', 'flags_opcode', 'flags_authoritative', 'flags_truncated', 'flags_recdesired', 'flags_recavail', 'flags_z', 'flags_authenticated', 'flags_checkdisable', 'flags_rcode', 'count_queries', 'count_answers', 'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 'qry_class', 'resp_name', 'resp_type', 'resp_class', 'resp_ttl', 'resp_len', 'cname', 'a', 'response_to', 'time']
            current_index = i
            # cap[i].dns.a.all_fields outputs all dns answer fields
            print(cap[i].dns.a.all_fields[0].get_default_value())           
            print(target_ip)
            break

# Get the conversation. 
# Get the first SYN done between the client and the target.ip, then get the socket. Finally, filter this conversation.

#Test to get the IP whether it is ipv4 or ipv6. 


for i in range(current_index, num_packets):
    if hasattr(cap[i], 'ip') or hasattr(cap[i], 'ipv6'):

        current_src = cap[i].ip.src if hasattr(cap[i], 'ip') else cap[i].ipv6.src

        current_dst = cap[i].ip.dst if hasattr(cap[i], 'ip') else cap[i].ipv6.dst
        
        if  current_src == src_ip and current_dst == target_ip and cap[i].tcp.flags_ack == '0' and cap[i].tcp.flags_syn =='1':
            # cap[i].tcp.field_names outputs: ['srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', '_ws_expert', 'connection_syn', '_ws_expert_message', '_ws_expert_severity', '_ws_expert_group', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'checksum', 'checksum_status', 'urgent_pointer', 'options', 'options_mss', 'option_kind', 'option_len', 'options_mss_val', 'options_nop', 'options_wscale', 'options_wscale_shift', 'options_wscale_multiplier', 'options_sack_perm', '', 'time_relative', 'time_delta']
            
            srcport = cap[i].tcp.srcport
            dstport = cap[i].tcp.dstport
            print(cap[i])
            current_index = i
            break


filter = '(ip.addr eq ' + str(src_ip) + ' and ip.addr eq '+ str(target_ip) +') and (tcp.port eq '+ str(srcport) +' and tcp.port eq '+ str(dstport) +')'
cap_filtered = pyshark.FileCapture(filename, display_filter=filter)
cap_filtered.load_packets()

print(len(cap_filtered))

print(cap_filtered[0])
print(cap_filtered[1])
print(cap_filtered[2].tcp.flags)

# print(target_conversation[0])
