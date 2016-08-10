/*
 *
 * write.h
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

#ifndef SHARKPY_WRITE_H_
#define SHARKPY_WRITE_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>
#include <pcap/pcap.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define MAX_DATALINK_DESC 2048

typedef struct {
	pcap_dumper_t *dumper;
	pcap_t *pd;
}dumpfile;

typedef void (*export_interface)(void *ifc_2_cpy);
export_interface save_interface_info;

int
copy_out_iface(pcap_if_t *ifc);

int
getInterfaceList(pcap_if_t **alldevsp, char *errbuf);

void
setInterfaceExportCallback(export_interface fnct);

unsigned int
getErrorBufferSize(void);

int
getNumberOfInterfaces(char *error);

/*
 * Returns interface count or -1 on error.
 * Triggers callback within that copies out
 * info about each interface to Python env.
 */
int
getInterfaceInfoList(char *errbuf);

dumpfile *
pcap_write_file(const char *in_file_path, char *errbuf);

int
pcap_write_packet(dumpfile *dumpobjs,
		          long epoch_seconds,
				  int epoch_remainder,
				  unsigned int datalen,
				  unsigned char *pktdata,
				  char *errbuf);

#endif /* SHARKPY_WRITE_H_ */

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
