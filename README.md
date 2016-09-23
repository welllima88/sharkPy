
#SharkPy is

Current version: beta 0.1

A python module to dissect, analyze, and interact with network packet data as native Python objects using Wireshark and libpcap capabilities. sharkPy dissect modules extend and otherwise modify Wireshark's tshark. SharkPy packet injection and pcap file writing modules wrap useful libpcap functionality.<br/>

SharkPy comes with six modules that allows one to explore, create, and/or modify packet data and (re)send data over network, and write (possibly modified) packets to a new pcap output file. This is all done within python program or interactive python session.<br/>

1. sharkPy.file_dissector -- dissect capture file packets using Wireshark's dissection libraries and present detailed packet dissections to caller as native Python objects.<br/>

2. sharkPy.wire_dissector -- capture packets from interface and dissect captured packets using Wireshark's dissection libraries. Presents packets to callers as native Python objects.<br/>

3. sharkPy.file_writer -- write (possibly modified) packets to a new output pcap file. For example, one can dissect packet capture file using sharkPy.file_dissector, create new packets based on the packets in the dissected file, and then write new/modified packets to an output pcap file.  

4. sharkPy.wire_writer -- write arbitrary data (e.g. modified packets) to specified network interface using libpcap functionality. Currently, sharkPy users are responsible for correctly building packets that are transmitted using this module's functionality. <br/>

5. sharkPy.utils -- a set of utility functions

6. sharkPy.protocol_blender -- protocol specific convenience functions. Currently contains functions for ipv4 and tcp over ipv4. 

##Versioning

current: beta 0.1 - flesh out desired functionality and api</br>
next:    beta 0.2 - refactor tshark code to modularize functionality and cross compile for Windows.</br>

##Design Goals

1. Deliver dissected packet data to callers as native python objects.<br/>

2. Provide functionality within a Python environment, either a python program or interactive python session. <br/>

3. Make commands non-blocking whenever reasonable providing command results to caller on-demand.<br/>

4. Be easy to understand and use assuming one understands Wireshark and python basics.<br/>

5. Pack functionality into a small number of commands.<br/>

6. Build and install as little C-code as possible by linking to preexisting Wireshark shared libs.<br/>

SharkPy is provided "as-is" with NO WARRANTIES expressed or implied under GPLv2. Use at your own risk.

##Why sharkPy?

SharkPy has a long-term goal of segmenting Wireshark's incredible diversity of capabilities into a set of shared libraries that are smaller, more modular, more easily compiled and linked into other projects. This goal seperates sharkPy from other similar efforts that endeavor to marry Wireshark/tshark and Python. 

The first step is provide Wireshark/tshark capabilities as Python modules that can be compiled/linked outside of Wireshark's normal build process. This has been achieved at least for some linux environments/distros. Next step is to expand to a broader range of linux distros and Windows improving stability along the way. Once this is completed and sharkPy's capabilities are similar to those provided by tshark, the sharkPy project devs will start the process of segmenting the code base as described above.

#HOW-TO

## sharkPy API -- examples in following sections

###Disecting packets from file
<b>dissect_file(file_path, options=[], timeout=10):</b> collect packets from packet capture file delivering packet dissections when requested using get_next function.<br/>
>>>>-- name of packet capture file.<br/>
>>>>-- collection and dissection options. Options are disopt.DECODE_AS and disopt.NAME_RESOLUTION.<br/>
>>>>-- timeout: amount of time (in seconds) to wait before file open fails.<br/>
>>>>-- RETURNS tuple (p, exit_event, shared_pipe).<br/>
>>>>>>>>--p: dissection process handle.<br/>
>>>>>>>>--exit_event: event handler used to signal that collection should stop.<br/>
>>>>>>>>-shared_pipe: shared pipe that dissector returns dissection trees into.<br/>
>>>>>>>>--NOTE: users should not directly interact with these return objects. Instead returned tuple is passed into get_next and close functions as input param.<br/>
        
<b>get_next(dissect_process,timeout=None):</b> get next available packet dissection.<br/>
>>>>-- dissect_process: tuple returned from dissect_file.<br/>
>>>>-- timeout: amount to time to wait (in seconds) before operation timesout.<br/>
>>>>-- RETURNS root node of packet dissection tree.<br/>
    
<b>close_file(dissect_process):</b> stop and clean up.<br/>
>>>>-- dissect_process: tuple returned from dissect_file.<br/>
>>>>-- RETURNS None.<br/>
>>>>-- NOTE: close MUST be called on each session.

###Disecting packets from wire
<b>dissect_wire(interface, options=[], timeout=None):</b> collect packets from interface delivering packet dissections when requested using get_next function.<br/>
>>>>-- name of interface to capture from.<br/>
>>>>-- collection and dissection options. Options are disopt.DECODE_AS, disopt.NAME_RESOLUTION, and disopts.NOT_PROMISCUOUS.<br/>
>>>>-- timeout: amount of time (in seconds) to wait before start capture fails.<br/>
>>>>-- RETURNS tuple (p, exit_event, shared_queue).<br/>
>>>>>>>>--p: dissection process handle.<br/>
>>>>>>>>--exit_event: event handler used to signal that collection should stop.<br/>
>>>>>>>>--shared_queue: shared queue that dissector returns dissection trees into.<br/>
>>>>>>>>--NOTE: users should not directly interact with these return objects. Instead returned tuple is passed into get_next and close functions as input param.<br/>
        
<b>get_next(dissect_process,timeout=None):</b> get next available packet dissection from live capture.<br/>
>>>>-- dissect_process: tuple returned from dissect_wire.<br/>
>>>>-- timeout: amount to time to wait (in seconds) before operation timesout.<br/>
>>>>-- RETURNS root node of packet dissection tree.<br/>
    
<b>close_wire(dissect_process):</b> stop and clean up from live capture.<br/>
>>>>-- dissect_process: tuple returned from dissect_wire.<br/>
>>>>-- RETURNS None.<br/>
>>>>-- NOTE: close MUST be called on each capture session.

### Writing data/packets on wire or to file
<b>wire_writer(write_interface_list):</b> wire_writer contructor. Used to write arbitrary data to interfaces.<br/>
>>>>-- write_interface_list: list of interface names to write to.<br/>
>>>>-- RETURNS: wire_writer object.<br/>
>>>>>>>>-- wire_writer.cmd: pass a command to writer.<br/>
>>>>>>>>>>>>--wr.cmd(command=wr.WRITE_BYTES, command_data=data_to_write , command_timeout=2)<br/>
>>>>>>>>>>>>--wr.cmd(command=wr.SHUT_DOWN_ALL,command_data=None,command_data=2)<br/>
>>>>>>>>>>>>--wr.cmd(command=wr.SHUT_DOWN_NAMED, command_data=interface_name, command_data=2)<br/>
>>>>>>>>-- wire_writer.get_rst(timeout=1): returns tuple (success/failure, number_of_bytes_written)<br/>
        
<b>file_writer():</b> Creates a new file_writer object to write packets to an output pcap file.<br/>
>>>>--<b>make_pcap_error_buffer():</b> Creates a correctly sized and initialized error buffer. <br/>
>>>>>>>>--Returns error buffer.<br/>
>>>>--<b>pcap_write_file(output_file_path, error_buffer):</b> create and open new pcap output file.<br/>
>>>>>>>>--output_file_path: path for newly created file.<br/>
>>>>>>>>--err_buffer:error buffer object returned by make_pcap_error_buffer(). Any errors messages will be written to this buffer. <br/>
>>>>>>>>--Returns: ctypes.c_void_p, which is a context object required for other write related functions.<br/>
>>>>--<b>pcap_write_packet(context, upper_time_val, lower_time_val, num_bytes_to_write, data_to_write, error_buffer):</b> writes packets to opened pcap output file.<br/>
>>>>>>>>--context: object returned by pcap_write_file().<br/>
>>>>>>>>--upper_time_val: packet epoch time in seconds. Can be first value in tuple returned from utility function get_pkt_times().<br/>
>>>>>>>>--lower_time_val: packet epoch time nano seconds remainder. Can be second value in tuple returned from utility function get_pkt_times().<br/>
>>>>>>>>--num_bytes_to_write: number of bytes to write to file, size of data buffer.<br/>
>>>>>>>>--data_to_write: buffer of data to write.<br/>
>>>>>>>>--err_buffer:error buffer object returned by make_pcap_error_buffer(). Any errors messages will be written to this buffer.<br/>
>>>>>>>>--RETURNS 0 on success, -1 on failure. Error message will be available in err_buffer.<br/>
>>>>--<b>pcap_close(context):</b> MUST be called to flush write buffer, close write file, and free allocated resources.<br/>
>>>>>>>>--context: object returned by pcap_write_file().<br/>
>>>>>>>>--RETURNS: None.<br/>
        
### Utility functions
<b>do_funct_walk(root_node, funct, aux=None):</b> recursively pass each node in dissection tree (and aux) to function. Depth first walk.<br/>
>>>>-- root_node: node in dissection tree that will be the first to be passed to function.<br/>
>>>>-- funct: function to call.<br/>
>>>>-- aux: optional auxilliary variable that will be passed in as parameter as part of each function call.<br/>
>>>>-- RETURNS None.<br/>
    
<b>get_node_by_name(root_node, name):</b> finds and returns a list of dissection nodes in dissection tree with a given name (i.e., 'abbrev').<br/>
 >>>>-- root_node: root of dissection tree being passed into function.<br/>
 >>>>-- name: Name of node used as match key. Matches again 'abbrev' attribute.<br/>
 >>>>-- RETURNS: a list of nodes in dissection tree with 'abbrev' attribute that matches name. NOTE: abbrev attribute is not necessarily unique in a given dissection. tree. This is the reason that this function returns a LIST of matching nodes.<br/>
     
<b>get_node_data_details(node):</b> Returns a tuple of values that describe the data in a given dissection node.<br/>
>>>>-- node: node that will have its details provided.<br/>
>>>>-- RETURNS: returns tuple, (data_len,first_byte_index, last_byte_index, data, binary_data).<br/>
>>>>>>>>-- data_len: number of bytes in node's data.<br/>
>>>>>>>>-- first_byte_index: byte offset from start of packet where this node's data starts.<br/>
>>>>>>>>-- last_byte_index: byte offset from start of packet where this node's data ends.<br/>
>>>>>>>>-- data: string representation of node data.<br/>
>>>>>>>>-- binary_data: binary representation of node data.<br/>
        
<b>get_pkt_times(pkt=input_packet):</b> Returns tuple containing packet timestamp information.<br/>
>>>>--pkt: packet dissection tree returned from one of sharkPy's dissection routines.<br/>
>>>>--RETURNS: The tuple (epoch_time_seconds, epoch_time_nanosecond_remainder). These two values are required for file_writer's <br/>
    
<b>find_replace_data(pkt, field_name, test_val, replace_with=None, condition_funct=condition_data_equals, enforce_bounds=True, quiet=True):</b> A general search, match, and replace data in packets.<br/>
>>>>-- pkt: packet dissection tree returned from one of sharkPy's dissection routines.<br/>
>>>>-- field_name: the 'abbrev' field name that will have its data modified/replaced.<br/>
>>>>-- test_val: data_val/buffer that will be used for comparison in matching function.<br/>
>>>>-- replace_with: data that will replace the data in matching dissection fields.<br/>
>>>>-- condition_funct: A function that returns True or False and has the prototype, condition_funct(node_val, test_val, pkt_dissection_tree). Default is the condition_data_equals() function that returns True if node_val == test_val. This is a literal byte for byte matching.<br/>
>>>>--enforce_bounds: If true, enforces condition that len(replace_with) == len(node_data_to_be_replaced). Good idea to keep this set to its default, which is True.<br/>
>>>>--quiet: If set to False, will print error msg to stdout if the target field 'abbrev' name cannot be found in packet dissection tree.<br/>
>>>>--RETURNS: new packet data represented as a hex string or None if target field is not in packet.<br/>
    
<b>condition_data_equals(node_val, test_val, pkt_dissection_tree=None):</b> A matching function that can be passed to find_replace_data().<br/>
>>>>-- node_val: value from the dissected packet that is being checked
>>>>-- test_val: value that node_val will be compared to.
>>>>-- pkt_dissection_tree: entire packet dissection tree. Not used in this comparison.
>>>>-- RETURNS True is a byte for byte comparison reveals that node_val == test_val. Otherwise, returns False.
    
<b>condition_always_true(node_val=None, test_val=None, pkt_dissection_tree=None):</b> A matching function that can be passed to find_replace_data().<br/>
>>>>-- node_val: Not used in this comparison<br/>
>>>>-- test_val: Not used in this comparison<br/>
>>>>-- pkt_dissection_tree: entire packet dissection tree. Not used in this comparison.<br/>
>>>>-- RETURNS True ALWAYS. Useful of the only matching criteria is that the target field exists in packet dissection.<br/>

###Protocol Blender

<b>ipv4_find_replace(pkt_dissection, src_match_value=None, dst_match_value=None, new_srcaddr=None, new_dstaddr=None, update_checksum=True, condition_funct=sharkPy.condition_data_equals):</b> Modifies select ipv4 fields.<br/>
	-- pkt_dissection: packet dissection tree.<br/>
	-- src_match_value: current source ip address to look for (in hex). This value will be replaced.<br/>
	-- dst_match_value: current destination ip address to look for (in hex). This value will be replaced.<br/>
	-- new_srcaddr: replace current source ip address with this ip address (in hex).<br/>
	-- new_dstaddr: replace current destination ip address with this ip address (in hex).<br/>
	-- update_checksum: fixup ipv4 checksum if True (default).<br/>
	-- condition_funct: matching function used to find correct packets to modify.<br/>
	
<b>tcp_find_replace(pkt_dissection, src_match_value=None, dst_match_value=None, new_srcport=None, new_dstport=None, update_checksum=True, condition_funct=sharkPy.condition_data_equals):</b> Modifies select fields for tcp over ipv4.
	-- pkt_dissection: packet dissection tree.<br/>
	-- src_match_value: current source tcp port to look for (in hex). This value will be replaced.<br/>
	-- dst_match_value: current destination tcp port to look for (in hex). This value will be replaced.<br/>
	-- new_srcaddr: replace current source tcp port with this tcp port (in hex).<br/>
	-- new_dstaddr: replace current destination tcp port with this tcp port (in hex).<br/>
	-- update_checksum: fixup tcp checksum if True (default).<br/>
	-- condition_funct: matching function used to find correct packets to modify.<br/>

##DISSECT PACKETS IN A CAPTURE FILE

\>>> import sharkPy<br/>

### Supported options so far are DECODE_AS and NAME_RESOLUTION (use option to disable)<br/>
\>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'),(sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http')]<br/>

### Start file read and dissection.<br/>
\>>> dissection=sharkPy.dissect_file(r'/home/me/capfile.pcap',options=in_options)<br/>

### Use sharkPy.get_next to get packet dissections of read packets.<br/>
rtn_pkt_dissections_list=[]
\>>> for cnt in xrange(13):<br/>
...     pkt=sharkPy.get_next(dissection)<br/>
...     rtn_pkt_dissections_list.append(pkt)

Node Attributes: <br/>
 abbrev:     frame.<br/>
 name:       Frame.<br/>
 blurb:      None.<br/>
 fvalue:     None.<br/>
 level:      0.<br/>
 offset:     0.<br/>
 ftype:      1.<br/>
 ftype_desc: FT_PROTOCOL.<br/>
 repr:       Frame 253: 54 bytes on wire (432 bits), 54 bytes captured (432 bits) on interface 0.<br/>
 data:       005056edfe68000c29....<rest edited out><br/>

Number of child nodes: 17<br/>
 frame.interface_id<br/>
 frame.encap_type<br/>
 frame.time<br/>
 frame.offset_shift<br/>
 frame.time_epoch<br/>
 frame.time_delta<br/>
 frame.time_delta_displayed<br/>
 frame.time_relative<br/>
 frame.number<br/>
 frame.len<br/>
 frame.cap_len<br/>
 frame.marked<br/>
 frame.ignored<br/>
 frame.protocols<br/>
 eth<br/>
 ip<br/>
 tcp<br/>


  Node Attributes: <br/>
   abbrev:     frame.interface_id.<br/>
   name:       Interface id.<br/>
   blurb:      None.<br/>
   fvalue:     0.<br/>
   level:      1.<br/>
   offset:     0.<br/>
   ftype:      6.<br/>
   ftype_desc: FT_UINT32.<br/>
   repr:       Interface id: 0 (eno16777736).<br/>
   data:       None.<br/>

  Number of child nodes: 0<br/>

...<remaining edited out><br/>

### Must always close sessions<br/>
\>>> sharkPy.close_file(dissection)<br/>

### Take a packet dissection tree and index all nodes by their names (abbrev field)<br/> 
\>>> pkt_dict={}<br/>
\>>> sharkPy.collect_proto_ids(rtn_pkt_dissections_list[0],pkt_dict)<br/>

### Here are all the keys used to index this packet dissection<br/>
\>>> print pkt_dict.keys()<br/>
['tcp.checksum_bad', 'eth.src_resolved', 'tcp.flags.ns', 'ip', 'frame', 'tcp.ack', 'tcp', 'frame.encap_type', 'eth.ig', 'frame.time_relative', 'ip.ttl', 'tcp.checksum_good', 'tcp.stream', 'ip.version', 'tcp.seq', 'ip.dst_host', 'ip.flags.df', 'ip.flags', 'ip.dsfield', 'ip.src_host', 'tcp.len', 'ip.checksum_good', 'tcp.flags.res', 'ip.id', 'ip.flags.mf', 'ip.src', 'ip.checksum', 'eth.src', 'text', 'frame.cap_len', 'ip.hdr_len', 'tcp.flags.cwr', 'tcp.flags', 'tcp.dstport', 'ip.host', 'frame.ignored', 'tcp.window_size', 'eth.dst_resolved', 'tcp.flags.ack', 'frame.time_delta', 'tcp.flags.urg', 'ip.dsfield.ecn', 'eth.addr_resolved', 'eth.lg', 'frame.time_delta_displayed', 'frame.time', 'tcp.flags.str', 'ip.flags.rb', 'tcp.flags.fin', 'ip.dst', 'tcp.flags.reset', 'tcp.flags.ecn', 'tcp.port', 'eth.type', 'ip.checksum_bad', 'tcp.window_size_value', 'ip.addr', 'ip.len', 'frame.time_epoch', 'tcp.hdr_len', 'frame.number', 'ip.dsfield.dscp', 'frame.marked', 'eth.dst', 'tcp.flags.push', 'tcp.srcport', 'tcp.checksum', 'tcp.urgent_pointer', 'eth.addr', 'frame.offset_shift', 'tcp.window_size_scalefactor', 'ip.frag_offset', 'tcp.flags.syn', 'frame.len', 'eth', 'ip.proto', 'frame.protocols', 'frame.interface_id']<br/>

### Note that pkt_dict entries are lists given that 'abbrevs' are not always unique within a packet.<br/>
\>>> val_list=pkt_dict['tcp']<br/>

### Turns out that 'tcp' list has only one element as shown below.<br/>
\>>> for each in val_list:<br/>
...     print each<br/>
... <br/>
Node Attributes: <br/>
 abbrev:     tcp.<br/>
 name:       Transmission Control Protocol.<br/>
 blurb:      None.<br/>
 fvalue:     None.<br/>
 level:      0.<br/>
 offset:     34.<br/>
 ftype:      1.<br/>
 ftype_desc: FT_PROTOCOL.<br/>
 repr:       Transmission Control Protocol, Src Port: 52630 (52630), Dst Port: 80 (80), Seq: 1, Ack: 1, Len: 0.<br/>
 data:       cd960050df6129ca0d993e7750107d789f870000.<br/>

Number of child nodes: 15<br/>
 tcp.srcport<br/>
 tcp.dstport<br/>
 tcp.port<br/>
 tcp.port<br/>
 tcp.stream<br/>
 tcp.len<br/>
 tcp.seq<br/>
 tcp.ack<br/>
 tcp.hdr_len<br/>
 tcp.flags<br/>
 tcp.window_size_value<br/>
 tcp.window_size<br/>
 tcp.window_size_scalefactor<br/>
 tcp.checksum<br/>
 tcp.urgent_pointer<br/>
 
### Short-cut for finding a node by name:<br/>
\>>> val_list=sharkPy.get_node_by_name(rtn_pkt_dissections_list[0], 'ip')<br/>

### Each node in a packet dissection tree has attributes and a child node list.<br/>
\>>> pkt = val_list[0]<br/>

### This is how one accesses attributes<br/>
\>>> print pkt.attributes.abbrev<br/>
tcp<br/>

\>>> print pkt.attributes.name<br/>
Transmission Control Protocol<br/>

### Here's the pkt's child list<br/>
\>>> print pkt.children<br/>
\[\<sharkPy.dissect.file_dissector.node object at 0x10fda90>,\<sharkPy.dissect.file_dissector.node object at 0x10fdb10>, \<sharkPy.dissect.file_dissector.node object at 0x10fdbd0>, \<sharkPy.dissect.file_dissector.node object at 0x10fdc90>, \<sharkPy.dissect.file_dissector.node object at 0x10fdd50>, \<sharkPy.dissect.file_dissector.node object at 0x10fddd0>, \<sharkPy.dissect.file_dissector.node object at 0x10fde50>, \<sharkPy.dissect.file_dissector.node object at 0x10fded0>, \<sharkPy.dissect.file_dissector.node object at 0x10fdf90>, \<sharkPy.dissect.file_dissector.node object at 0x1101090>, \<sharkPy.dissect.file_dissector.node object at 0x11016d0>, \<sharkPy.dissect.file_dissector.node object at 0x11017d0>, \<sharkPy.dissect.file_dissector.node object at 0x1101890>, \<sharkPy.dissect.file_dissector.node object at 0x1101990>, \<sharkPy.dissect.file_dissector.node object at 0x1101b50>]<br/>

### Get useful information about a dissection node's data<br/>
\>>> data_len, first_byte_offset, last_byte_offset, data_string_rep, data_binary_rep=sharkPy.get_node_data_details(pkt)<br/>

\>>> print data_len<br/>
54<br/>

\>>> print first_byte_offset<br/>
0<br/>

\>>> print last_byte_offset<br/>
53<br/>

\>>> print data_string_rep<br/>
005056edfe68000c29....\<rest edited out><br/>

\>>> print binary_string_rep<br/>
\<prints binary spleg, edited out><br/>


## CAPTURE PACKETS FROM NETWORK AND DISSECT THEM

### SharkPy wire_dissector provides additional NOT_PROMISCUOUS option<br/>
\>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'),(sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http'),(sharkPy.disopt.NOT_PROMISCUOUS,None)]<br/>

### Start capture and dissection. Note that caller must have appropriate permissions. Running as root could be dangerous! <br/>
\>>> dissection=sharkPy.dissect_wire(r'eno16777736',options=in_options)<br/>
\>>> Running as user "root" and group "root". This could be dangerous.<br/>

### Use sharkPy.get_next to get packet dissections of captured packets.<br/>
\>>> for cnt in xrange(13):<br/>
...     pkt=sharkPy.get_next(dissection)<br/>
...     sharkPy.walk_print(pkt) ##much better idea to save pkts in a list<br/>

### Must always close capture sessions<br/>
\>>> sharkPy.close_wire(dissection)<br/>

## WRITE DATA (packets) TO NETWORK

### Create writer object using interface name<br/>
\>>> wr=sharkPy.wire_writer(['eno16777736'])<br/>

### Send command to write data to network with timeout of 2 seconds<br/>
\>>> wr.cmd(wr.WRITE_BYTES,'  djwejkweuraiuhqwerqiorh',2)<br/>

### Check for failure. If successful, get return values.
\>>> if(not wr.command_failure.is_set()):<br/>
...     print wr.get_rst(1)<br/>
... <br/>
(0, 26) ### returned success and wrote 26 bytes. ###<br/>

## WRITE PACKETS TO OUTPUT PCAP FILE

### Create file writer object<br/>
\>>> fw=file_writer()<br/>

### Create error buffer<br/>
\>>> errbuf=fw.make_pcap_error_buffer()<br/>

### Open/create new output pcap file into which packets will be written<br/>
\>>> outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)<br/>

### Dissect packets in an existing packet capture file.<br/>
\>>> sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcap',timeout=20)<br/>

### Write first packet into output pcap file.<br/>

#### Get first packet dissection<br/>
\>>>pkt_dissection=sorted_rtn_list[0]<br/>

#### Acquire packet information required for write operation
\>>>pkt_frame = sharkPy.get_node_by_name(pkt_dissection, 'frame')<br/>
\>>>frame_data_length, first_frame_byte_index, last_frame_byte_index, frame_data_as_string, frame_data_as_binary = sharkPy.get_node_data_details(pkt_frame[0])<br/>
\>>>utime, ltime = sharkPy.get_pkt_times(pkt_dissection)<br/>

#### Write packet into output file<br/>
\>>>fw.pcap_write_packet(outfile, utime,ltime,frame_data_length,frame_data_as_binary,errbuf)<br/>

### Close output file and clean-up<br/>
\>>> fw.pcap_close(outfile)<br/>

## MATCH AND REPLACE BEFORE WRITING NEW PACKETS TO OUTPUT PCAP FILE
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

