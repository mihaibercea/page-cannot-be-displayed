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
    if frame.dns.qry_name==host:
        #print(frame.dns.id)
        dns_id = frame.dns.id
        #print(frame.dns.flags_response)
        src_ip = frame.ip.src_host
        print(src_ip)

for frame in cap_dns:
    if frame.dns.id == dns_id and frame.dns.flags_response == '1':
        # print(frame)
        # print(frame.dns.field_names)
        # print(type(frame.dns.flags_response))        
        # print(frame.dns.a)
        target_ip = frame.dns.a

# Get the conversation

target_conversation = []

print(cap[2].ip if hasattr(cap[2], 'ip') else print(cap[2].ipv6))

# for frame in cap:
#     if frame.ip and frame.ip.dst == target_ip:
#         target_conversation.append(frame)

# print(target_conversation[0])

