import sharkPy, binascii
from sharkPy.protocol_blender import ipv4_blender

test_value1=r'c0a84f81'
test_value2=r'c0a84f02'
test_value3=r'005056c00008'

fw=sharkPy.file_writer()
errbuf=fw.make_pcap_error_buffer()
outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)
sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcap',timeout=20)

for pkt in sorted_rtn_list:

    #do eth erc replacement
    new_str_data= sharkPy.find_replace_data(pkt, test_value3, r'eth.src', r'005050505050')
    
    #forward ip replace
    new_str_data=ipv4_blender.ipv4_find_replace(pkt,test_value1, test_value2, r'01010101', r'02020202')
    
    #reverse ip replace
    new_str_data=ipv4_blender.ipv4_find_replace(pkt,test_value2, test_value1, r'02020202', r'01010101')

       
    #get details required to write to output pcap file
    pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
    fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
    utime, ltime = sharkPy.get_pkt_times(pkt)
    
    if(new_str_data is None):
        new_str_data=fd
    
    newbd = binascii.a2b_hex(new_str_data)
    fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)

fw.pcap_close(outfile)


