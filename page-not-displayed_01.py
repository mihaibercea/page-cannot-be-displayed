import numpy as np
import pyshark
import typer
from ipaddress import ip_address, IPv4Address
  
def validIPAddress(IP: str) -> str:
    try:
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"
  
# Get the capture

app = typer.Typer()


@app.command()
def ip(filename: str,  ip: str):
    
    print(f"Your ip: {ip}")

    if validIPAddress(ip) == "Invalid":
        print(f'Your IP is invalid: {ip}')
    
    else:

        cap = pyshark.FileCapture(filename)

        # Get the DNS query for the target host

        cap_dns = pyshark.FileCapture(filename, display_filter='dns')

        # print("what is the target host?\n Input below:\n" )

        # host = input()
        current_index = 0
        target_ip = ip
        #cap = cap_dns
        cap.load_packets()

        num_packets = len(cap)
        print(len(cap))   

        # Get the conversation. 
        # Get the first SYN done between the client and the target.ip, then get the socket. Finally, filter this conversation.

        conversations = []

        for i in range(current_index, num_packets):
            if hasattr(cap[i], 'ip') or hasattr(cap[i], 'ipv6'):

                current_src = cap[i].ip.src if hasattr(cap[i], 'ip') else cap[i].ipv6.src

                current_dst = cap[i].ip.dst if hasattr(cap[i], 'ip') else cap[i].ipv6.dst
                
                if current_dst == target_ip and cap[i].tcp.flags_ack == '0' and cap[i].tcp.flags_syn =='1':
                    # cap[i].tcp.field_names outputs: ['srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', '_ws_expert', 'connection_syn', '_ws_expert_message', '_ws_expert_severity', '_ws_expert_group', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'checksum', 'checksum_status', 'urgent_pointer', 'options', 'options_mss', 'option_kind', 'option_len', 'options_mss_val', 'options_nop', 'options_wscale', 'options_wscale_shift', 'options_wscale_multiplier', 'options_sack_perm', '', 'time_relative', 'time_delta']
                    src_ip = current_src
                    srcport = cap[i].tcp.srcport
                    dstport = cap[i].tcp.dstport
                    print(cap[i])
                    print('tcp seq is: '+ cap[i].tcp.seq)            

                    # Get the relative sequence number and filter for the current conversation in order to understand if the full TCP handshake is done.
                    
                    if cap[i].tcp.seq == '0':
                        filter = '(ip.addr eq ' + str(src_ip) + ' and ip.addr eq '+ str(target_ip) +') and (tcp.port eq '+ str(srcport) +' and tcp.port eq '+ str(dstport) +')'
                        current_conv = pyshark.FileCapture(filename, display_filter=filter)
                        current_conv.load_packets()

                        if len(current_conv)>1 and current_conv[1].tcp.flags_ack == '1' and current_conv[1].tcp.flags_syn =='1' and current_conv[2].tcp.flags_ack == '1' and current_conv[2].tcp.flags_syn =='0':
                            
                            conversations.append(current_conv)

                            print("TCP connection detected: \n")
                            print("Use the following filter: "+ filter + '\n')
                            print(current_conv[0])
                            print(current_conv[1])
                            print(current_conv[2])
                            current_index = i

                            for j in range(3, len(current_conv)):
                                if hasattr(current_conv[j], 'tls'):
                                    if hasattr(current_conv[j].tls,  'handshake') and current_conv[j].tls.handshake  == 'Handshake Protocol: Client Hello':

                                        print('success')
                                        print('TLS handshake detected: \n')
                                        print(current_conv[j])
                                        # current_conv[3].tls.field_names outputs: ['record', 'record_content_type', 'record_version', 'record_length', 'handshake', 'handshake_type', 'handshake_length', 'handshake_version', 'handshake_random', 'handshake_random_time', 'handshake_random_bytes', 'handshake_session_id_length', 'handshake_session_id', 'handshake_cipher_suites_length', 'handshake_ciphersuites', 'handshake_ciphersuite', 'handshake_comp_methods_length', 'handshake_comp_methods', 'handshake_comp_method', 'handshake_extensions_length', '', 'handshake_extension_type', 'handshake_extension_len', 'handshake_extension_data', 'handshake_extensions_server_name_list_len', 'handshake_extensions_server_name_type', 'handshake_extensions_server_name_len', 'handshake_extensions_server_name', 'handshake_extensions_reneg_info_len', 'handshake_extensions_supported_groups_length', 'handshake_extensions_supported_groups', 'handshake_extensions_supported_group', 'handshake_extensions_ec_point_formats_length', 'handshake_extensions_ec_point_formats', 'handshake_extensions_ec_point_format', 'handshake_extensions_alpn_len', 'handshake_extensions_alpn_list', 'handshake_extensions_alpn_str_len', 'handshake_extensions_alpn_str', 'handshake_extensions_status_request_type', 'handshake_extensions_status_request_responder_ids_len', 'handshake_extensions_status_request_exts_len', 'handshake_sig_hash_alg_len', 'handshake_sig_hash_algs', 'handshake_sig_hash_alg', 'handshake_sig_hash_hash', 'handshake_sig_hash_sig', 'handshake_extensions_key_share_client_length', 'handshake_extensions_key_share_group', 'handshake_extensions_key_share_key_exchange_length', 'handshake_extensions_key_share_key_exchange', 'extension_psk_ke_modes_length', 'extension_psk_ke_mode', 'handshake_extensions_supported_versions_len', 'handshake_extensions_supported_version', 'compress_certificate_algorithms_length', 'compress_certificate_algorithm', 'handshake_extensions_alps_len', 'handshake_extensions_alps_alpn_list', 'handshake_extensions_alps_alpn_str_len', 'handshake_extensions_alps_alpn_str','handshake_extensions_padding_data', 'handshake_ja3_full', 'handshake_ja3']

                                        # print(current_conv[5].tls.handshake)
                                        # print(current_conv[10])
                                        # print(current_conv[10].tls.field_names)
                                        # print(current_conv[11])
                                        # print(current_conv[11].tls.field_names)
                                    
                        


    print('If no data is shown, it means that no conversation was found for the specified IP')


@app.command()
def url(filename: str, url: str):
    
    print(f"Your URL:  {url}")

    cap = pyshark.FileCapture(filename)

    # Get the DNS query for the target host

    cap_dns = pyshark.FileCapture(filename, display_filter='dns')

    # print("what is the target host?\n Input below:\n" )

    # host = input()

    host = url
    #cap = cap_dns
    cap.load_packets()

    num_packets = len(cap)
    print("Number of packets in the specified trace: " + len(cap))

    for i in range(num_packets):
        if 'DNS' in cap[i]:
            if (cap[i].dns.qry_name==host or cap[i].dns.qry_name=='www.'+host) and cap[i].dns.flags_response == '0':

                #print(cap[i])
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

                target_ips =[]
                for j in range(len(cap[i].dns.a.all_fields)):
                    target_ips.append(cap[i].dns.a.all_fields[j].get_default_value())
                print(cap[i].dns.a.all_fields[0].get_default_value())           
                print(target_ips)
                break

    # Get the conversation. 
    # Get the first SYN done between the client and the target.ip, then get the socket. Finally, filter this conversation.

    conversations = []

    for i in range(current_index, num_packets):
        if hasattr(cap[i], 'ip') or hasattr(cap[i], 'ipv6'):

            current_src = cap[i].ip.src if hasattr(cap[i], 'ip') else cap[i].ipv6.src

            current_dst = cap[i].ip.dst if hasattr(cap[i], 'ip') else cap[i].ipv6.dst
            
            if  current_src == src_ip and current_dst in target_ips and cap[i].tcp.flags_ack == '0' and cap[i].tcp.flags_syn =='1':
                # cap[i].tcp.field_names outputs: ['srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', '_ws_expert', 'connection_syn', '_ws_expert_message', '_ws_expert_severity', '_ws_expert_group', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'checksum', 'checksum_status', 'urgent_pointer', 'options', 'options_mss', 'option_kind', 'option_len', 'options_mss_val', 'options_nop', 'options_wscale', 'options_wscale_shift', 'options_wscale_multiplier', 'options_sack_perm', '', 'time_relative', 'time_delta']
                
                srcport = cap[i].tcp.srcport
                dstport = cap[i].tcp.dstport
                print(cap[i])
                print('tcp seq is: '+ cap[i].tcp.seq)            

                # Get the relative sequence number and filter for the current conversation in order to understand if the full TCP handshake is done.
                
                if cap[i].tcp.seq == '0':
                    filter = '(ip.addr eq ' + str(src_ip) + ' and ip.addr eq '+ str(target_ip) +') and (tcp.port eq '+ str(srcport) +' and tcp.port eq '+ str(dstport) +')'
                    current_conv = pyshark.FileCapture(filename, display_filter=filter)
                    current_conv.load_packets()

                    if len(current_conv)>1 and current_conv[1].tcp.flags_ack == '1' and current_conv[1].tcp.flags_syn =='1' and current_conv[2].tcp.flags_ack == '1' and current_conv[2].tcp.flags_syn =='0':
                        
                        conversations.append(current_conv)

                        print("TCP connection detected: \n")
                        print("Use the following filter: "+ filter + '\n')
                        print(current_conv[0])
                        print(current_conv[1])
                        print(current_conv[2])
                        current_index = i

                        for j in range(3, len(current_conv)):
                            if hasattr(current_conv[j], 'tls'):
                                if hasattr(current_conv[j].tls,  'handshake') and current_conv[j].tls.handshake  == 'Handshake Protocol: Client Hello':

                                    print('success')
                                    print('TLS handshake detected: \n')
                                    print(current_conv[j])
                                    # current_conv[3].tls.field_names outputs: ['record', 'record_content_type', 'record_version', 'record_length', 'handshake', 'handshake_type', 'handshake_length', 'handshake_version', 'handshake_random', 'handshake_random_time', 'handshake_random_bytes', 'handshake_session_id_length', 'handshake_session_id', 'handshake_cipher_suites_length', 'handshake_ciphersuites', 'handshake_ciphersuite', 'handshake_comp_methods_length', 'handshake_comp_methods', 'handshake_comp_method', 'handshake_extensions_length', '', 'handshake_extension_type', 'handshake_extension_len', 'handshake_extension_data', 'handshake_extensions_server_name_list_len', 'handshake_extensions_server_name_type', 'handshake_extensions_server_name_len', 'handshake_extensions_server_name', 'handshake_extensions_reneg_info_len', 'handshake_extensions_supported_groups_length', 'handshake_extensions_supported_groups', 'handshake_extensions_supported_group', 'handshake_extensions_ec_point_formats_length', 'handshake_extensions_ec_point_formats', 'handshake_extensions_ec_point_format', 'handshake_extensions_alpn_len', 'handshake_extensions_alpn_list', 'handshake_extensions_alpn_str_len', 'handshake_extensions_alpn_str', 'handshake_extensions_status_request_type', 'handshake_extensions_status_request_responder_ids_len', 'handshake_extensions_status_request_exts_len', 'handshake_sig_hash_alg_len', 'handshake_sig_hash_algs', 'handshake_sig_hash_alg', 'handshake_sig_hash_hash', 'handshake_sig_hash_sig', 'handshake_extensions_key_share_client_length', 'handshake_extensions_key_share_group', 'handshake_extensions_key_share_key_exchange_length', 'handshake_extensions_key_share_key_exchange', 'extension_psk_ke_modes_length', 'extension_psk_ke_mode', 'handshake_extensions_supported_versions_len', 'handshake_extensions_supported_version', 'compress_certificate_algorithms_length', 'compress_certificate_algorithm', 'handshake_extensions_alps_len', 'handshake_extensions_alps_alpn_list', 'handshake_extensions_alps_alpn_str_len', 'handshake_extensions_alps_alpn_str','handshake_extensions_padding_data', 'handshake_ja3_full', 'handshake_ja3']

                                    # print(current_conv[5].tls.handshake)
                                    # print(current_conv[10])
                                    # print(current_conv[10].tls.field_names)
                                    # print(current_conv[11])
                                    # print(current_conv[11].tls.field_names)                                 
                        

if __name__ == "__main__":
    app()

