/*
 *
 * write.c
 *
 * author: Mark Landriscina<mlandri1@jhu.edu
 * Created on: Jul 31, 2016
 *
 * writer wraps libpcap functionality in such a way as to make it easy to call
 * using Python's ctype module. Basically, this is listing/opening interfaces and
 * writing data to given interfaces.
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
 *
 */


#include "write.h"

struct pcap_pkhdr_t{
	struct timeval ts;
	unsigned int caplen;
	unsigned int len;
};

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
 * Create/open new pcap output file
 */
dumpfile *
pcap_write_file(const char *in_file_path, char *errbuf)
{
	pcap_dumper_t *rtn_dump = NULL;
	dumpfile *dumpobjs = NULL;
	pcap_t *pd = NULL;
    char *errmsg=NULL;

    if(NULL == in_file_path)
    {
    	errmsg = "Error. NULL input parameter.";
    	goto fail;
    }

	if(NULL == (pd=pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65535, PCAP_TSTAMP_PRECISION_NANO)))
	{
		errmsg="pcap_open_dead() failed.";
        goto fail;
	}

    if( NULL == (rtn_dump=pcap_dump_open(pd, in_file_path)))
    {
		errmsg="pcap_dump_open() failed.";
        goto fail;
    }

    if (NULL == (dumpobjs = calloc(1,sizeof(dumpfile))))
    {
		errmsg="memory allocation for dump objects failed.";
        goto fail;
    }

    dumpobjs->dumper=rtn_dump;
    dumpobjs->pd = pd;

fail:
    if(NULL == rtn_dump && NULL != pd)
    {
    	pcap_close(pd);
    }

	if( NULL == rtn_dump && NULL != errbuf )
	{
		memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
		memcpy(errbuf, errmsg, strnlen(errmsg, PCAP_ERRBUF_SIZE-1));
	}
    return dumpobjs;
}

int
pcap_write_packet(dumpfile *dumpobjs,
		          long epoch_seconds,
				  int epoch_remainder,
				  unsigned int datalen,
				  unsigned char *pktdata,
				  char *errbuf)
{
	int rtn = 0;
    struct pcap_pkhdr_t phdr = {{epoch_seconds, epoch_remainder}, 0, 0};
    char *errmsg=NULL;
    pcap_dumper_t *dumper = NULL;

    if(NULL == dumpobjs || NULL == pktdata)
    {
    	errmsg = "Error. NULL input parameter.";
    	rtn = -1;
    	goto fail;
    }

    dumper = dumpobjs->dumper;
    phdr.caplen=datalen;
    phdr.len=datalen;

    pcap_dump((unsigned char *)dumper,(const struct pcap_pkthdr *)&phdr,pktdata);
    pcap_dump_flush(dumpobjs->dumper);

fail:
	if( rtn <0 && NULL != errbuf )
	{
		memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
		memcpy(errbuf, errmsg, strnlen(errmsg, PCAP_ERRBUF_SIZE-1));
	}
    return rtn;
}

void
close_pcap_dump(dumpfile *dumpobjs)
{
	if(NULL == dumpobjs          ||
	   NULL == dumpobjs->pd      ||
	   NULL == dumpobjs->dumper)
	{
		goto fail;
	}

	pcap_dump_close(dumpobjs->dumper);
    pcap_close(dumpobjs->pd);
    free(dumpobjs);

fail:
    ;
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






