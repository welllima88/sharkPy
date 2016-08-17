#!/usr/bin/python

import sharkPy

def ipv4_checksum_fixup(ip_hex_string):
       
    #add up all 16 bit fields in first 20 bytes of header (not including options)
    sums=0
    for cnt in xrange(0,40,4):

        if(20==cnt):
            val=0
        else:
            val=int(ip_hex_string[cnt:cnt+4],16)
        
        sums+=val
    
    #4 most significant bits are carry bits.
    carry=(sums>>16)&0xf

    #16 least significant bits are sum
    sums&=0xffff

    while(True):
        
        #break when carry bits == 0
        if(0==carry):
            break
        
        #carry gets added to sum
        sums+=carry
        
        #repeat carry/sum addition if carry bits != 0
        carry=(sums>>16)&0xf
        sums&=0xffff
    
    #flip all bits in sum to get checksum, convert to hex string, and pad as needed
    chksum=hex(0xffff^sums)[2:]
    padding = '0'*(4-len(chksum))

    return padding+chksum

# need to continue fleshing this out to encompass most if not all ip header fields 
def ipv4_find_replace(pkt,
                      src_match_value=None,
                      dst_match_value=None,
                      new_srcaddr=None,
                      new_dstaddr=None,
                      update_checksum=True,
                      condition_funct=sharkPy.condition_data_equals):
    
    cf=condition_funct
    new_str_data=None
    frame_data=sharkPy.get_node_by_name(pkt,'frame')[0].attributes.data
    
    #nothing to do if not ip packet. return original frame data
    try:
        sharkPy.get_node_by_name(pkt, 'ip')
    except Exception as e:
        
        return frame_data
    
    #nothing to do if not requesting changes. return orig frame data
    if(new_srcaddr is None and 
       new_dstaddr is None    ):
        
        return frame_data
    
    if(new_srcaddr is not None):
        new_str_data= sharkPy.find_replace_data(pkt, src_match_value, r'ip.src', new_srcaddr, condition_funct=cf, up_propagate=update_checksum)    
    if(new_dstaddr is not None):
        new_str_data= sharkPy.find_replace_data(pkt, dst_match_value, r'ip.dst', new_dstaddr, condition_funct=cf, up_propagate=update_checksum)
        
    if(True==update_checksum):
        
        ip=None
        new_checksum=None
        
        try:
            ip=sharkPy.get_node_by_name(pkt, 'ip')[0].attributes.data
        except Exception as e:
            print str(e)
            raise e      #something bad and unexpected happened
        
        #If changes have been made to ip header, fixup ip checksum
        if(ip is not None):
            old_checksum=sharkPy.get_node_by_name(pkt, r'ip.checksum')[0].attributes.data
            new_checksum=ipv4_checksum_fixup(ip)
            new_str_data= sharkPy.find_replace_data(pkt, new_checksum, r'ip.checksum', new_checksum, condition_funct=sharkPy.condition_data_not_equals,up_propagate=True)

    #return str hex rep of new packet data (after changes)
    return new_str_data
    

#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    
    #pass hex string representation of ip header bytes
    chksum=ipv4_checksum("4500004543f80000ff11870ac0a84f01e00000fb")
    
    if('870a' != chksum):
        raise RuntimeError("Failed to correctly calculate ip header")
    
    print hex(chksum)
    
    