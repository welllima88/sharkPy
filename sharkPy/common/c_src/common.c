/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * ###########################################################################
 *
 * writer
 *
 * writer author: Mark Landriscina
 * Created on: Feb 1, 2016
 *
 * writer wraps libpcap functionality in such a way as to make it easy to call
 * using Python's ctype module. Basically, this is listing/opening interfaces and
 * writing data to given interfaces. This code is released under same terms and
 * conditions as is Wireshark. See above.
 *
 *###########################################################################
 */


#include "common.h"

typedef struct {
    unsigned int flags;
    const char *description;
    const char *name;
    unsigned int openable;
    char *datalink_types;

} interfaceInfo;

int
copy_out_iface(pcap_if_t *ifc)
{
    int rtn = 0;
    int cnt = 0;
    interfaceInfo newIface = {0};
    pcap_t *ifcHandle = NULL;
    char errBuffer[PCAP_ERRBUF_SIZE];
    int *dlts = NULL;
    int dlt=0;
    int numdlts=0;
    char dl_buf[MAX_DATALINK_DESC];
    int byteCnt=0;
    char *name=NULL;
    char *ptr=NULL;

    if( NULL == ifc )
    {
    	rtn = -1;
    	goto fail;
    }

    memset(dl_buf,'\0',MAX_DATALINK_DESC);
    memset(errBuffer,'\0',PCAP_ERRBUF_SIZE);

    newIface.description = ifc->description;
    newIface.name = ifc->name;
    newIface.flags = ifc->flags;

    /*
     * Attempt to open interface
     */
    if ( NULL == (ifcHandle = pcap_open_live(ifc->name, 65535,0,0,errBuffer)) )
    {
    	newIface.openable = 0;
    } else {
    	newIface.openable = 1;
    	if (0 > (numdlts = pcap_list_datalinks(ifcHandle,&dlts)) )
    	{
    		goto fail;
    	}

    	ptr=dl_buf;
    	for(cnt=0;cnt<numdlts && byteCnt<MAX_DATALINK_DESC-1;++cnt)
    	{
            dlt=dlts[cnt];
            if (NULL != (name=(char *)pcap_datalink_val_to_name(dlt)) && MAX_DATALINK_DESC-1>byteCnt+strlen(name)+1)
            {
                memcpy(ptr,name,strlen(name));
                ptr += (strlen(name));
                memset(ptr,',',1);
                ptr+=1;
                byteCnt += ((strlen(name)) + 1);
            }
    	}

        /*
         * Overwrite last comma with whitespace, then assign buffer to newIface.datalink_types.
         */
        *(ptr-1)=' ';
        newIface.datalink_types = dl_buf;
    }

    /*
     * Call out to Python function that copies interface information out
     * into Python object.
     */
    save_interface_info( &newIface );

fail:
    if (NULL != dlts)
    {
    	pcap_free_datalinks(dlts);
    }
    if (NULL != ifcHandle)
    {
    	pcap_close(ifcHandle);
    }
    return rtn;
}

void
setInterfaceExportCallback(export_interface fnct)
{
	if(NULL != fnct)
	{
		save_interface_info = fnct;
	}
}

unsigned int
getErrorBufferSize(void)
{
	return (PCAP_ERRBUF_SIZE);
}

int
getNumberOfInterfaces(char *error)
{
	int rtn=0;
	int cnt = 0;
	pcap_if_t *alldevs=NULL;
	pcap_if_t *ptr = NULL;

	memset(error,'\0',PCAP_ERRBUF_SIZE);

	if ( 0 != (rtn = getInterfaceList( &alldevs, error ) ))
	{
		goto fail;
	}

	ptr=alldevs;
	while (NULL != ptr)
	{
		++cnt;
		ptr=ptr->next;
	}

	rtn = cnt;

fail:

    if( NULL != alldevs )
    {
    	pcap_freealldevs(alldevs);
    }

	return rtn;
}

int
getInterfaceInfoList(char *errbuf)
{
	int rtn=0;
	int cnt = 0;
	pcap_if_t *alldevs=NULL;
	pcap_if_t *ptr = NULL;

	memset(errbuf,'\0',PCAP_ERRBUF_SIZE);

	if ( 0 != (rtn = getInterfaceList( &alldevs, errbuf ) ))
	{
		goto fail;
	}

	ptr=alldevs;
	while (NULL != ptr)
	{
		copy_out_iface(ptr);
		ptr=ptr->next;
	}

	rtn = cnt;

fail:

    if( NULL != alldevs )
    {
    	pcap_freealldevs(alldevs);
    }

    return rtn;
}

int
getInterfaceList(pcap_if_t **alldevsp, char *errbuf)
{
    int rtn = 0;
    char *errmsg=NULL;
    pcap_if_t *devs = NULL;


    if( NULL == alldevsp)
    {
    	errmsg = "Error. Input interface pointer not provided.";
    	rtn = -1;
    	goto fail;
    }

    else if( NULL == errbuf )
    {
        /*
         * Don't have an error buffer to write error message into
         */
    	rtn = -1;
    	goto fail;
    }

    if ( 0 != (rtn = pcap_findalldevs( &devs, errbuf ) ))
    {
    	goto fail;
    }

    if( NULL == devs )
    {
    	errmsg="pcap_findalldevs returned success. However, no iterfaces found. Check your permissions.";
    	rtn=-1;
    	goto fail;
    }

    *alldevsp = devs;

fail:

    if( rtn <0 && NULL != errbuf )
    {
    	memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
    	memcpy(errbuf, errmsg, strnlen(errmsg, PCAP_ERRBUF_SIZE-1));
    }

    if( rtn <0 && NULL != devs )
    {
    	/*
    	 * clean-up on error.
    	 */
    	pcap_freealldevs(devs);
    }

    return rtn;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */






