import sharkPy, binascii

test_value1=r'0xc0a84f01'
test_value2=r'c0a84fff'
test_value3=r'005056c00008'

fw=sharkPy.file_writer()
errbuf=fw.make_pcap_error_buffer()
outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)
sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcap',timeout=20)

for pkt in sorted_rtn_list:

    #do replacement
    new_str_data= sharkPy.find_replace_data(pkt, r'ip.src', test_value1, r'01010101')
    new_str_data= sharkPy.find_replace_data(pkt, r'ip.dst', test_value2, r'02020202')
    new_str_data= sharkPy.find_replace_data(pkt, r'eth.src', test_value3, r'005050505050')
    
    #get detains required to write to output pcap file
    pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
    fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
    utime, ltime = sharkPy.get_pkt_times(pkt)
    
    if(new_str_data is None):
        new_str_data=fd
    
    newbd = binascii.a2b_hex(new_str_data)
    fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)

fw.pcap_close(outfile)