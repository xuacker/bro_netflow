/// See the file "COPYING" in the main distribution directory for copyright.

#include "bro-config.h"

#include "NetVar.h"
#include "NETFLOW.h"
#include "Sessions.h"
#include "Event.h"
#include <ctime>
#include <cstring>

#include "events.bif.h"

using namespace analyzer::netflow;





NETFLOW_Analyzer::NETFLOW_Analyzer(Connection* conn)
        : Analyzer("NETFLOW", conn)
{
}



void NETFLOW_Analyzer::Done()
{
    Analyzer::Done();
    Event(udp_session_done);
}

void NETFLOW_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64 seq, const IP_Hdr* ip, int caplen)
{
    Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

    // Actually we could just get rid of the Request/Reply and simply use
    // the code of Message().  But for now we use it as an example of how
    // to convert an old-style UDP analyzer.
    if ( is_orig )
        Message(data, len);
}



void NETFLOW_Analyzer::Message(const u_char* data, int len)
{
    if ( (unsigned) len < sizeof(struct netflow_v5_header) )
    {
        Weird("truncated_Netflow");
        return;
    }

    netflow_v5_header_t	*v5_header;
    netflow_v5_record_t *v5_record;
    uint64_t	start_time, end_time,boot_time;
    double export_time;
    uint32_t   	First, Last;
//    uint32_t    dpkts,octects;
    uint16_t	count;
    uint8_t		flags;
    int			i, done, version, flow_record_length;
    ssize_t		size_left;

    uint32_t cfirst,clast;
    uint16_t  msec_first,msec_last;

    //cfirst cmsec_first  clast cmsec_last

    v5_header 	= (netflow_v5_header_t *)data;
    version = ntohs(v5_header->version);
    if (version != 5){
        Weird("wrong _Netflow version");
        return;
    }
    flow_record_length = NETFLOW_V5_RECORD_LENGTH;
    size_left = len;
//    done = 0;
//    while ( !done ) {
    count	= ntohs(v5_header->count);
    if ( count > NETFLOW_V5_MAX_RECORDS ) {
        Weird("Process_v5: Unexpected record count in header");
        return;
    }
    if ( size_left < ( NETFLOW_V5_HEADER_LENGTH + count * flow_record_length) ) {
        Weird("Process_v5: Not enough data to process v5 record");
        return;
    }

    v5_header->SysUptime	 = ntohl(v5_header->SysUptime);
    v5_header->unix_secs	 = ntohl(v5_header->unix_secs);
    v5_header->unix_nsecs	 = ntohl(v5_header->unix_nsecs);

    export_time = v5_header->unix_secs + ((uint32_t)v5_header->unix_nsecs) / 1e9;


    v5_record	= (netflow_v5_record_t *)((pointer_addr_t)v5_header + NETFLOW_V5_HEADER_LENGTH);
    for (i = 0; i < count; i++) {

        First	 				= ntohl(v5_record->First);
        Last		 			= ntohl(v5_record->Last);



        start_time = export_time - (((uint32_t)v5_header->SysUptime) - First) * Milliseconds;


        end_time = export_time - (((uint32_t)v5_header->SysUptime) - Last) * Milliseconds;

        val_list* vl = new val_list;
        vl->append(BuildConnVal());
//        vl->append(new Val((double)start_time, TYPE_DOUBLE));
        vl->append(new Val((double)start_time, TYPE_DOUBLE));
        vl->append(new Val((double)end_time, TYPE_DOUBLE));
        vl->append(new AddrVal(v5_record->srcaddr));
        vl->append(new AddrVal(v5_record->dstaddr));
        vl->append(new Val((unsigned int)ntohs(v5_record->srcport), TYPE_COUNT));
        vl->append(new Val((unsigned int)ntohs(v5_record->dstport), TYPE_COUNT));
        vl->append(new Val(v5_record->prot, TYPE_COUNT));
        vl->append(new Val((unsigned int)ntohl(v5_record->dPkts), TYPE_COUNT));
        vl->append(new Val((unsigned int)ntohl(v5_record->dOctets), TYPE_COUNT));

        ConnectionEvent(netflow5_message, vl);
        v5_record		= (netflow_v5_record_t *)((pointer_addr_t)v5_record + flow_record_length);
    }

}
