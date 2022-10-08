import numpy as np
import pyshark

# Get the capture
cap = pyshark.FileCapture('traces/karatedojo.pcapng')

# Get the DNS query for the target host

cap_dns = pyshark.FileCapture('traces/karatedojo.pcapng', display_filter='dns')

# print("what is the target host?\n Input below:\n" )

# host = input()

host = 'karatedojo.ro'

for frame in cap_dns:
    if frame.dns.qry_name==host and frame.dns.flags_response == 0:
        #print(frame.dns.id)
        dns_id = frame.dns.id
        #print(frame.dns.flags_response)
        src_ip = frame.ip.src_host
        print(src_ip)        
        break

for frame in cap_dns:
    if frame.dns.id == dns_id and frame.dns.flags_response == '1':
        # print(frame)
        # print(frame.dns.field_names)
        # print(type(frame.dns.flags_response))        
        # print(frame.dns.a)
        target_ip = frame.dns.a
        print(target_ip)
        break

# Get the conversation. 
# Get the first SYN done between the client and the target.ip, then get the socket. Finally, filter this conversation.

#Test to get the IP whether it is ipv4 or ipv6. 
# 
# print(cap[2].ip if hasattr(cap[2], 'ip') else print(cap[2].ipv6.dst))
#print(cap[2])

cap_filtered = pyshark.FileCapture('traces/karatedojo.pcapng', display_filter=('ip.addr == '+ str(target_ip)))
# for frame in cap_filtered:
#     print(frame)
for frame in cap_filtered:
    if hasattr(frame, 'ip') or hasattr(frame, 'ipv6'):

        current_src = frame.ip.src if hasattr(frame, 'ip') else frame.ipv6.src

        current_dst = frame.ip.dst if hasattr(frame, 'ip') else frame.ipv6.dst
        
        if  current_src == src_ip and current_dst == target_ip:
            print(frame.field_names)
            break

# print(target_conversation[0])

