#!/usr/bin/python

import sharkPy

def tcp_find_replace(pkt,
                     src_match_value=None,
                     dst_match_value=None,
                     new_srcport=None,
                     new_dstport=None,
                     update_checksum=True,
                     condition_funct=sharkPy.condition_data_equals):
    
    old_checksum=None
    new_checksum=None
    checksum_target=None
    tcp_node=None
    tcp_data=None
    tcp_first_byte = None
    cf=condition_funct
    new_str_data=None
    frame_data=sharkPy.get_node_by_name(pkt,'frame')[0].attributes.data
    
    #nothing to do if not tcp packet. ignore and return original frame data.
    try:
        tcp_node=sharkPy.get_node_by_name(pkt, 'tcp')[0]
    except Exception as e:
        return None

    #replace src/dst ports.
    if(new_srcport is not None):
        new_str_data= sharkPy.find_replace_data(pkt, src_match_value, r'tcp.srcport', new_srcport, condition_funct=cf, up_propagate=update_checksum)    
    if(new_dstport is not None):
        new_str_data= sharkPy.find_replace_data(pkt, dst_match_value, r'tcp.dstport', new_dstport, condition_funct=cf, up_propagate=update_checksum)
       
        
    
#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    
    fhdrlen=None
    tcpseglen=None
    tcpseglendata=None
    sorted_rtn_list=sharkPy.dissect_file(r'/home/me/Downloads/cb(1).pcap',timeout=20)
    for pkt in sorted_rtn_list:
        pass        
        

    

    