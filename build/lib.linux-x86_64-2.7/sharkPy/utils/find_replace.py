#!/usr/bin/python

from sharkPy import *
import binascii, re

def up_propagate_change(target_node_name, pkt):
    
    names=target_node_name.split('.')
    if(2>len(names)):
        return
    
    while(len(names)>1):
        child_name='.'.join(names)
        names.remove(names[-1])
        parent_name='.'.join(names)
        parent=get_node_by_name(pkt, parent_name)[0]
        child=get_node_by_name(pkt, child_name)[0]
        
        child_offset=child.attributes.offset
        parent_offset=parent.attributes.offset
        offset_diff=child_offset-parent_offset
     
        tmp=parent.attributes.data[:]
        parent.attributes.data=parent.attributes.data[:offset_diff*2]
        parent.attributes.data+=child.attributes.data[:]
        parent.attributes.data+=tmp[offset_diff*2+len(child.attributes.data):]

        names=parent_name.split('.')

def condition_always_true(node_val=None, test_val=None, pkt_dissection_tree=None):
    return True

def condition_data_equals(node_val, test_val, pkt_dissection_tree=None):
    return(node_val == test_val)

def condition_data_not_equals(node_val, test_val, pkt_dissection_tree=None):
    return(node_val != test_val)

def find_replace_data(pkt, test_val, field_name, replace_with=None, condition_funct=condition_data_equals, enforce_bounds=True, up_propagate=False, quiet=True):
    
    node_list=None
    hex_replace=None
    hex_test_val=None
    frame_node=None
    frame_data_string=''
    
    #verify as hex
    try:
        int(replace_with,16)
    except Exception as e:
        raise AttributeError("Replace_with parameter MUST be hexadecimal string.")
    
    #verify as hex
    try:
        int(test_val,16)
    except Exception as e:
        raise AttributeError("Test_val parameter MUST be hexadecimal string.")
    
    m=re.match(r'(0[xX])([0-9a-fA-F]+)', replace_with)
    hex_replace=replace_with
    if(m is not None):
        hex_replace=m.group(2)
        
    m=re.match(r'(0[xX])([0-9a-fA-F]+)', test_val)
    hex_test_val=test_val
    if(m is not None):
        hex_test_val=m.group(2)
        
    if(len(hex_replace)%2 or 0 ==len(hex_replace)):
        raise AttributeError("Replace_with parameter MUST be hexadecimal string with an even number of characters with length greater than one.")
    
    try:
        node_list=get_node_by_name(pkt, field_name)
    except Exception as e:
        
        if(False == quiet):
            print str(e) #prints error message
        
    if(node_list is None or 0 == len(node_list)):
        return None
    
    try:
        frame_node=get_node_by_name(pkt, 'frame')[0]
    except Exception as e:
        print str(e)
        raise e   #fatal error
        
    fdl, ffb, flb, frame_data_string, fdb = get_node_data_details(frame_node)
    
    if(frame_data_string is None or 0 == len(frame_data_string)):
        raise RuntimeError("Failed to acquire packet data from dissection tree.")
    
    for node in node_list:
        
        new_data_string = ''
        data_len, first_byte_index, last_byte_index, data_as_string, data_as_binary = get_node_data_details(node)
        
        if(True == enforce_bounds and len(hex_replace)!=data_len*2):
            raise AttributeError("Enforcing field bounds and replacement byte length is different from field byte length:" +str(len(hex_replace)/2)+','+str(data_len/2))
    
        if(False == condition_funct(data_as_string, hex_test_val, pkt)):
            continue
    
        offset = first_byte_index*2+data_len*2
        new_data_string+=frame_data_string[:first_byte_index*2]
        new_data_string+=hex_replace[:]
        new_data_string+=frame_data_string[offset:]
        frame_data_string=new_data_string[:]
        
        #modify packet dissection data for this node
        node.attributes.data=hex_replace[:]
        
        #if requested, propagate changes up the dissection tree from child to parent upto frame.
        #really have to know what you're doing if you enable this option
        #required if field interdependancies arise such as fixing up ip checksum after modifying header
        if(True == up_propagate):
            up_propagate_change(node.attributes.abbrev, pkt)

    #changing data values for both target node and frame in packet dissection allows one to call find_replace_data
    #multiple times in series.
    frame_node.attributes.data=frame_data_string[:]
    
    
    
    return frame_data_string



#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    

    test_value1=r'0xc0a84f01'
    test_value2=r'c0a84fff'
    test_value3=r'005056c00008'

    fw=file_writer()
    errbuf=fw.make_pcap_error_buffer()
    outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)
    sorted_rtn_list=dissect_file(r'/home/me/tst.pcap',timeout=20)

    for pkt in sorted_rtn_list:

        #do replacement
        new_str_data= find_replace_data(pkt, r'ip.src', test_value1, r'01010101')
        new_str_data= find_replace_data(pkt, r'ip.dst', test_value2, r'02020202')
        new_str_data= find_replace_data(pkt, r'eth.src', test_value3, r'005050505050')
        
        #get detains required to write to output pcap file
        pkt_frame = get_node_by_name(pkt, 'frame')
        fdl, ffb, flb, fd, fbd = get_node_data_details(pkt_frame[0])
        utime, ltime = get_pkt_times(pkt)
        
        if(new_str_data is None):
            new_str_data=fd
        
        newbd = binascii.a2b_hex(new_str_data)
        fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)
    
    fw.pcap_close(outfile)
        
        