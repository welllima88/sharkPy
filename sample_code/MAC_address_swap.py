#!/usr/bin/python

#
# Open and dissect packets in saved pcap file.
#
# Swap source and destination MAC addresses for all dissected packets and 
# write modified packets to new pcap file.
#
import sharkPy, binascii

fw=sharkPy.file_writer()
errbuf=fw.make_pcap_error_buffer()
outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)

sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcap',timeout=20)


for pkt in sorted_rtn_list:
    pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
    src_eth = sharkPy.get_node_by_name(pkt, 'eth.src')
    dst_eth = sharkPy.get_node_by_name(pkt, 'eth.dst')
    
    fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
    utime, ltime = sharkPy.get_pkt_times(pkt)
    
    esdl, esfb, eslb, esd, esbd = sharkPy.get_node_data_details(src_eth[0])
    eddl, edfb, edlb, edd, edbd = sharkPy.get_node_data_details(dst_eth[0])
    
    #swap dst and src eth addresses
    new_str_data=esd
    new_str_data+=edd
    new_str_data+=fd[(eslb+1)*2:]
    
    newbd = binascii.a2b_hex(new_str_data)
    
    fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)
    
fw.pcap_close(outfile)
