#smtp  pop3 imap  ftp http telnet dns sip  snmp  netflow


const telnet_ports = { 23/tcp };
const pop3_ports = { 110/tcp };
const imap_ports = { 143/tcp };
const netflow_ports = { 12345/udp };

event bro_init() {
    Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, pop3_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, imap_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_NETFLOW, netflow_ports);
    
}


#	msg->Assign(3, new Val((unsigned int) ntp_data->ppoll, TYPE_COUNT));
#	msg->Assign(10, new Val(LongFloat(ntp_data->xmt), TYPE_TIME));
#vl->append(new AddrVal(htonl(addr)));


# event netflow5_message%(u: connection, stime: time, etime:time, src_h:addr, dst_h:addr,src_p:count, dst_p:count, pt:count,pkts:count, Octets:count%);

# event login_input_line(c: connection, line: string){
#     print "<-", line;
# }

# event login_output_line(c: connection, line: string){
#     print "->", line;
# }


# event sip_request(c: connection, method: string, original_URI:  string, version: string){
#     print method;
#     print original_URI;
# }

# event sip_reply(c: connection, version: string, code: count, reason: string){
#     print version;
#     print code;
#     print reason;
# }

# event sip_all_headers(c: connection, is_orig: bool, hlist:  mime_header_list){
#     local strCommand: string;
#     if (is_orig) {
#         print "client";

#     }else{
#         print "server";
#     }
#         for (h in hlist) {
#             strCommand = fmt("%s:%s",hlist[h]$name,hlist[h]$value);
#             print strCommand;
#             # print hlist[h]$value;
#         }

# }

# event snmp_get_request(c: connection, is_orig: bool, header:  SNMP::Header, pdu: SNMP::PDU){
#     print "get##########";
#     print header;
#     print pdu;

# }

# event snmp_response(c: connection, is_orig: bool, header:  SNMP::Header, pdu: SNMP::PDU){
#     print "response##################";
#     print header;
#     print pdu;
# }

# event snmp_set_request(c: connection, is_orig: bool, header:  SNMP::Header, pdu: SNMP::PDU){
#     print "set###############";
#     print header;
#     print pdu;
# }

# event pop3_request(c: connection, is_orig: bool, command:  string, arg: string){
#     print "request ##############";
#     print command;
#     print arg;
# }

# event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string){
#     print "reply ############";
#     print cmd;
#     print msg;
# }

# event pop3_login_success(c: connection, is_orig: bool, user: string, password: string){
#     print "login #########";
#     print user;
#     print password;
# }

# event pop3_starttls(c: connection){
#     print "fuck";
# }

# event pop3_data(c: connection, is_orig: bool, data: string){
#     print "server ###########";
#     if (! is_orig){
#     print data;
#     }
# }

# event mime_begin_entity(c: connection){

# }

# event mime_end_entity(c: connection){

# }

# event mime_all_headers(c: connection, hlist: mime_header_list){
#     local strCommand: string;
    
#     if (c$id$resp_p == 143/tcp){
#         print "mime headers#####################";
#         for (h in hlist) {
#             strCommand = fmt("%s:%s",hlist[h]$name,hlist[h]$value);
#             print strCommand;
#             # print hlist[h]$value;
#         }
#         print "#################################";
#     }

# }

# event mime_all_data(c: connection, length: count, data: string){
    
#     if (c$id$resp_p == 143/tcp){
        
#         print "###########################";        
#         print data;
#         print "##########################";
#     }
# }

# event imap_capabilities(c: connection, capabilities: string_vec){
#     print capabilities;
# }

# event imap_starttls(c: connection){
#     print c;
# }


# event imap_request(c: connection,  is_orig: bool, command: string, arg: string){
#     print "imap request";
#     # print command;
#     # if (command == "LOGIN"){
#         print command;
#         print arg;
#     # }
# }


# event imap_reply(c: connection, is_orig: bool, code: string, msg: string){
#     print code;
# }

# event imap_data(c:connection, is_orig: bool, mail_segment_t:bool ,cmd:string, arg:string){
#     # print cmd;
#     if (mail_segment_t){
#         print arg;
#     }
# }


event netflow5_message(u: connection, stime: double, etime:double, src_h:addr, dst_h:addr,src_p:count, dst_p:count, pt:count,pkts:count, Octets:count){
    # print u;
    # print stime;

    # local mhr_first_detected = double_to_time(stime);
	# local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
    # print readable_first_detected;

    # print etime;
    # print src_h;
    # print dst_h;
    # print src_p;
    # print dst_p;
    # print pt;
    # print pkts;
    # print Octets;

}