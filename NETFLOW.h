// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_NETFLOW_NETFLOW_H
#define ANALYZER_PROTOCOL_NETFLOW_NETFLOW_H

#include "analyzer/protocol/udp/UDP.h"
#include <stdint.h>

// The following are from the tcpdump distribution, credited there
// to the U of MD implementation.


#define NETFLOW_V5_HEADER_LENGTH 24
#define NETFLOW_V5_RECORD_LENGTH 48
#define NETFLOW_V5_MAX_RECORDS	 30

namespace analyzer { namespace netflow {

typedef uint64_t    pointer_addr_t;

typedef struct netflow_v5_header {
	uint16_t  version;
	uint16_t  count;
	uint32_t  SysUptime;
	uint32_t  unix_secs;
	uint32_t  unix_nsecs;
	uint32_t  flow_sequence;
	uint16_t	engine_tag;
	uint16_t  sampling_interval;
} netflow_v5_header_t;

typedef struct netflow_v5_record {
	uint32_t  srcaddr;
	uint32_t  dstaddr;
	uint32_t  nexthop;
	uint16_t  input;
	uint16_t  output;
	uint32_t  dPkts;
	uint32_t  dOctets;
	uint32_t  First;
	uint32_t  Last;
	uint16_t  srcport;
	uint16_t  dstport;
	uint8_t   pad1;
	uint8_t   tcp_flags;
	uint8_t   prot;
	uint8_t   tos;
	uint16_t  src_as;
	uint16_t  dst_as;
	uint8_t   src_mask;
	uint8_t   dst_mask;
	uint16_t  pad2;
} netflow_v5_record_t;


class NETFLOW_Analyzer : public analyzer::Analyzer {
public:
	NETFLOW_Analyzer(Connection* conn);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NETFLOW_Analyzer(conn); }

protected:
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);


	void Message(const u_char* data, int len);


};

} } // namespace analyzer::* 

#endif
