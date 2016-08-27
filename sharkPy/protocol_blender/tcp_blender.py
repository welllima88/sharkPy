#!/usr/bin/python

import sharkPy, binascii, struct


def get_pseudoheader(pkt):
    
    srcaddr=sharkPy.get_node_by_name(pkt, 'ip.src')[0].attributes.data
    dstaddr=sharkPy.get_node_by_name(pkt, 'ip.dst')[0].attributes.data
    res="00"
    protocol="06"
    
    pseudo_len=12
    hdr_len=int(sharkPy.get_node_by_name(pkt, 'tcp.hdr_len')[0].attributes.fvalue)
    tcp_len=int(sharkPy.get_node_by_name(pkt, 'tcp.len')[0].attributes.fvalue)
    
    total_len=hex((hdr_len+tcp_len)&0xffff)[2:].zfill(4)
    ph=srcaddr+dstaddr+res+protocol+total_len
    return ph

def compute_tcp_checksum(pkt):
    
    ph=get_pseudoheader(pkt)
    tcp_checksum=sharkPy.get_node_by_name(pkt,'tcp.checksum')[0].attributes.data
    sharkPy.find_replace_data(pkt,tcp_checksum,'tcp.checksum',"0000",up_propagate=True)
    
    tcp=sharkPy.get_node_by_name(pkt, 'tcp')[0].attributes.data
    tcp_offset=int(sharkPy.get_node_by_name(pkt, 'tcp')[0].attributes.offset)
    tcp_seg=ph+sharkPy.get_node_by_name(pkt, 'frame')[0].attributes.data[tcp_offset*2:]
    
    while(len(tcp_seg)%4):
        tcp_seg+="00"
    
    sums=0
    for cnt in xrange(0,len(tcp_seg),4):

        val=int(tcp_seg[cnt:cnt+4],16)
        
        sums+=val
    
    #4 most significant bits are carry bits.
    carry=(sums>>16)&0xffff

    #16 least significant bits are sum
    sums&=0xffff

    while(True):
               
        #break when carry bits == 0
        if(0==carry):
            break
                
        #carry gets added to sum
        sums+=carry
        
        #repeat carry/sum addition if carry bits != 0
        carry=(sums>>16)&0xffff
        sums&=0xffff
    
    #flip all bits in sum to get checksum, convert to hex string, and pad as needed
    chksum=hex(0xffff^sums)[2:].zfill(4)

    return chksum    
        

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
        new_str_data= sharkPy.find_replace_data(pkt, src_match_value, r'tcp.srcport', new_srcport, condition_funct=cf, up_propagate=True)    
    if(new_dstport is not None):
        new_str_data= sharkPy.find_replace_data(pkt, dst_match_value, r'tcp.dstport', new_dstport, condition_funct=cf, up_propagate=True)
        
    if(update_checksum):
        tcp_checksum_fixup(pkt)
        
def tcp_checksum_fixup(pkt):
    
    cs=compute_tcp_checksum(pkt)
    new_str_data=sharkPy.find_replace_data(pkt, "0000", r'tcp.checksum', cs, up_propagate=True)

#local test function
def write_packet(fw, pkt, outfile, new_utime=None, new_ltime=None):
    
    #make error buffer
    errbuf=fw.make_pcap_error_buffer()

    #get details required to write to output pcap file
    pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
    fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
    utime, ltime = sharkPy.get_pkt_times(pkt)
    
    if(new_utime is not None):
        utime=new_utime
        
    if(new_ltime is not None):
        ltime=new_ltime
    
    #make bin data and write packet to file
    newbd = binascii.a2b_hex(fd)
    fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)
    
#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    
    fhdrlen=None
    tcpseglen=None
    tcpseglendata=None
    new_pcap=(r'/home/me/tcp_fix.pcap')
    dissection=sharkPy.dissect_file(r'/home/me/Downloads/noise.pcap',timeout=20)
    server_port=hex(1337)[2:].zfill(4)
    new_server_port=hex(8080)[2:].zfill(4)
    client_port=hex(57180)[2:].zfill(4)
    new_client_port=hex(55555)[2:].zfill(4)
    
    #open output packet capture
    fw=sharkPy.file_writer()
    errbuf=fw.make_pcap_error_buffer()
    outfile=fw.pcap_write_file(new_pcap, errbuf)
    
    while(dissection is not None and True):
        
        try: 
            #get pkt 
            pkt=sharkPy.get_next_from_file(dissection)
                        
        except Exception as e:
            break
        
        pkt_src=sharkPy.get_node_by_name(pkt, 'tcp.srcport')[0].attributes.data
        if(pkt_src==client_port):
            tcp_find_replace(pkt, client_port, server_port, new_client_port, new_server_port)
        else:
            tcp_find_replace(pkt, server_port, client_port, new_server_port, new_client_port)

        write_packet(fw,pkt,outfile)

    fw.pcap_close(outfile)
    
    