#!/usr/bin/python

from sharkPy import collect_proto_ids
import binascii

#do funct for node, then for each child node. Walk down tree from root node.
def do_funct_walk(root_node, funct, aux=None):
    
    try:
        funct(root_node,aux)
    except Exception as e:
        print str(e)
        
    for child in root_node.children:
        do_funct_walk(child, funct, aux)


#returns list nodes in packet with abbrev value of name
def get_node_by_name(root_node, name):
    ndict={}
    nkeys=None
    
    try:
        collect_proto_ids(root_node, ndict)
    except Exception as e:
        print str(e)
        
    nkeys=ndict.keys()
    if name not in nkeys:
        raise AttributeError(str(name)+" not found.")
    
    return ndict[name]

def get_pkt_times(pkt):
    
    tnode=None
    tvals=[]
    
    try:
        tnode=get_node_by_name(pkt, 'frame.time_epoch')
    except Exception as e:
        print str(e)
        
    time_representation=tnode[0].attributes.fvalue
    tvals=time_representation.split('.')
    
    if(len(tvals) != 2):
        raise RuntimeError("malformed frame time value.")
    
    upper=int(tvals[0])
    lower=int(tvals[1])
    
    return ((upper,lower))
    
#returns tuple as follows: 
#node data length
#index of first byte in dissected packet
#index of last byte in dissected packet
#string representation of node data
#binary representation of node data
def get_node_data_details(node):
    
    data_len=0
    data=None
    first_byte_index=0
    last_byte_index=0
    binary_data=None
    if(node.attributes.data is None or node.attributes.data=='None.'):
        raise AttributeError(node.attributes.abbrev+": no data found")
    
    if(len(node.attributes.data)%2):
        raise AttributeError(node.attributes.abbrev+
                             ": data length must be even. Node length was "+
                             str(len(node.attributes.data)+"."))
    
    data=node.attributes.data
    data_len=len(data)/2
    first_byte_index=node.attributes.offset
    last_byte_index=node.attributes.offset+data_len-1
    binary_data=binascii.a2b_hex(data)
    
    return( (data_len,first_byte_index, last_byte_index, data, binary_data) )











#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    pass