% Copyright (c)2013 YAMAMOTO Takashi,
% All rights reserved.
%
% Redistribution and use in source and binary forms, with or without
% modification, are permitted provided that the following conditions
% are met:
% 1. Redistributions of source code must retain the above copyright
%    notice, this list of conditions and the following disclaimer.
% 2. Redistributions in binary form must reproduce the above copyright
%    notice, this list of conditions and the following disclaimer in the
%    documentation and/or other materials provided with the distribution.
%
% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
% ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
% SUCH DAMAGE.

-module(aloha_packet_test).

-include("aloha_packet.hrl").

-include_lib("eunit/include/eunit.hrl").

tcp_bin() ->
    <<242,11,164,149,235,12,0,3,71,140,161,179,8,0,69,0,0,162,0,0,64,0,64,6,182,75,192,0,2,1,192,0,2,9,31,144,210,224,0,0,0,1,180,110,233,188,80,16,11,184,54,65,0,0,72,84,84,80,47,49,46,49,32,50,48,48,32,79,75,13,10,99,111,110,110,101,99,116,105,111,110,58,32,107,101,101,112,45,97,108,105,118,101,13,10,115,101,114,118,101,114,58,32,67,111,119,98,111,121,13,10,100,97,116,101,58,32,77,111,110,44,32,49,50,32,65,117,103,32,50,48,49,51,32,49,52,58,52,48,58,50,51,32,71,77,84,13,10,99,111,110,116,101,110,116,45,108,101,110,103,116,104,58,32,55,13,10,13,10,97,108,111,104,97,33,10>>.

tcp_term() ->
    [#ether{dst = <<242,11,164,149,235,12>>,
            src = <<0,3,71,140,161,179>>,
            type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 162,id = 0,
         df = 1,mf = 0,offset = 0,ttl = 64,protocol = tcp,
         checksum = good,
         src = <<192,0,2,1>>,
         dst = <<192,0,2,9>>,
         options = <<>>},
     #tcp{src_port = 8080,dst_port = 53984,seqno = 1,
          ackno = 3027167676,data_offset = 5,urg = 0,ack = 1,psh = 0,
          rst = 0,syn = 0,fin = 0,window = 3000,checksum = good,
          urgent_pointer = 0,options = []},
     {bin,<<"HTTP/1.1 200 OK\r\nconnection: keep-alive\r\nserver: Cowboy\r\ndate: Mon, 12 Aug 2013 14:40:23 GMT\r\ncontent-length: 7\r\n\r\naloha!\n">>}].

tcp_bin2() ->
    <<0,3,71,140,161,179,142,17,145,26,179,75,8,0,69,0,0,64,0,0,64,0,64,6,182,174,192,0,2,8,192,0,2,1,226,97,31,144,218,159,58,11,0,0,0,0,176,2,128,0,27,86,0,0,2,4,5,180,1,3,3,3,4,2,1,1,1,1,8,10,0,0,0,1,0,0,0,0>>.

tcp_term3() ->
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<142,17,145,26,179,75>>,
            type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 45,id = 0,
         df = 1,mf = 0,offset = 0,ttl = 64,protocol = tcp,
         checksum = good,
         src = <<192,0,2,8>>,
         dst = <<192,0,2,1>>,
         options = <<>>},
     #tcp{src_port = 57665,dst_port = 9999,seqno = 1464125446,
          ackno = 65,data_offset = 5,urg = 0,ack = 1,psh = 1,rst = 0,
          syn = 0,fin = 0,window = 33580,checksum = good,
          urgent_pointer = 0,options = []},
     {bin,<<"heh\r\n">>}].

tcp_bin3() ->
    <<0,3,71,140,161,179,142,17,145,26,179,75,8,0,69,0,0,45,0,0,64,0,64,6,182,193,192,0,2,8,192,0,2,1,225,65,39,15,87,68,200,6,0,0,0,65,80,24,131,44,166,65,0,0,104,101,104,13,10,0>>.

tcp_term2() ->
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<142,17,145,26,179,75>>,
            type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 64,id = 0,
         df = 1,mf = 0,offset = 0,ttl = 64,protocol = tcp,
         checksum = good,
         src = <<192,0,2,8>>,
         dst = <<192,0,2,1>>,
         options = <<>>},
     #tcp{src_port = 57953,dst_port = 8080,seqno = 3667868171,
          ackno = 0,data_offset = 11,urg = 0,ack = 0,psh = 0,rst = 0,
          syn = 1,fin = 0,window = 32768,checksum = good,
          urgent_pointer = 0,
          options = [{mss,1460},
                     noop, 
                     {wscale,3}, 
                     sack_permitted,
                     noop,noop,noop,noop,
                     {timestamp,1,0}]}].

icmpv6_bin() ->
    <<51,51,0,0,0,1,142,17,145,26,179,75,134,221,96,0,0,0,0,16,58,64,254,128,0,0,0,0,0,0,240,11,164,255,254,89,204,18,255,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1,128,0,143,163,121,176,0,0,81,252,207,28,0,1,248,73>>.

icmpv6_term() ->
    [#ether{dst = <<51,51,0,0,0,1>>,
            src = <<142,17,145,26,179,75>>,
            type = ipv6},
     #ipv6{version = 6,traffic_class = 0,flow_label = 0,
           payload_length = 16,next_header = icmpv6,hop_limit = 64,
           src = <<254,128,0,0,0,0,0,0,240,11,164,255,254,89,204,18>>,
           dst = <<255,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>},
     #icmpv6{type = echo_request,code = 0,checksum = good,
             data = <<121,176,0,0,81,252,207,28,0,1,248,73>>}].

neighbor_solicitation_bin() ->
    <<51,51,255,0,0,1,142,17,145,26,179,75,134,221,96,0,0,0,0,32,58,255,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2,255,2,0,0,0,0,0,0,0,0,0,1,255,0,0,1,135,0,75,177,0,0,0,0,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,1,1,142,17,145,26,179,75>>.

neighbor_solicitation_term() ->
    [#ether{
         dst = <<51,51,255,0,0,1>>,
         src = <<142,17,145,26,179,75>>,
         type = ipv6},
     #ipv6{
         version = 6,traffic_class = 0,flow_label = 0,
         payload_length = 32,next_header = icmpv6,hop_limit = 255,
         src = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2>>,
         dst = <<255,2,0,0,0,0,0,0,0,0,0,1,255,0,0,1>>},
     #icmpv6{
         type = neighbor_solicitation,code = 0,checksum = good,
         data = 
             #neighbor_solicitation{
                 target_address = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>,
                 options = 
                     [{source_link_layer_address,<<142,17,145,26,179,75>>}]}}].

neighbor_advertisement_bin() ->
    <<142,17,145,26,179,75,0,3,71,140,161,179,134,221,96,0,0,0,0,32,58,255,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2,136,0,163,49,96,0,0,0,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,2,1,0,3,71,140,161,179>>.

neighbor_advertisement_term() ->
    [#ether{
         dst = <<142,17,145,26,179,75>>,
         src = <<0,3,71,140,161,179>>,
         type = ipv6},
     #ipv6{
         version = 6,traffic_class = 0,flow_label = 0,
         payload_length = 32,next_header = icmpv6,hop_limit = 255,
         src = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>,
         dst = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2>>},
     #icmpv6{
         type = neighbor_advertisement,code = 0,checksum = good,
         data = 
             #neighbor_advertisement{
                 router = 0,solicited = 1,override = 1,
                 target_address = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>,
                 options = 
                     [{target_link_layer_address,<<0,3,71,140,161,179>>}]}}].

arp_bin() ->
    <<242,11,164,149,235,12,0,3,71,140,161,179,8,6,0,1,8,0,6,4,0,2,0,3,71,140,161,179,192,0,2,1,242,11,164,149,235,12,192,0,2,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

arp_term() ->
    [#ether{dst = <<242,11,164,149,235,12>>,
            src = <<0,3,71,140,161,179>>,
            type = arp},
     #arp{hrd = 1,pro = ip,hln = 6,pln = 4,op = reply,
          sha = <<0,3,71,140,161,179>>,
          spa = <<192,0,2,1>>,
          tha = <<242,11,164,149,235,12>>,
          tpa = <<192,0,2,9>>},
     {bin,<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}].

icmp_bin() ->
    <<0,3,71,140,161,179,242,11,164,149,235,12,8,0,69,0,0,84,220,4,0,0,255,1,91,153,192,0,2,9,192,0,2,1,8,0,97,173,21,237,0,1,159,59,12,0,0,0,0,0,175,21,52,17,0,0,0,0,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,0,0,0,0,0,0,0,0>>.

icmp_term() ->
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<242,11,164,149,235,12>>,
            type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 84,
         id = 56324,df = 0,mf = 0,offset = 0,ttl = 255,
         protocol = icmp,checksum = good,
         src = <<192,0,2,9>>,
         dst = <<192,0,2,1>>,
         options = <<>>},
     #icmp{type = echo_request,code = 0,checksum = good,
           data = <<21,237,0,1,159,59,12,0,0,0,0,0,175,21,52,17,0,
                    0,0,0,16,17,18,19,20,21,22,23,24,25,26,27,28,
                    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,
                    44,45,46,47,0,0,0,0,0,0,0,0>>}].

ip_frag_bin() ->
    <<0,3,71,140,161,179,26,249,192,230,163,71,8,0,69,0,0,60,2,95,0,120,255,1,52,221,192,0,2,11,192,0,2,1,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,0,0,0,0,0,0,0,0>>.

ip_frag_term() ->
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<26,249,192,230,163,71>>,
            type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 60,id = 607,
         df = 0,mf = 0,offset = 120,ttl = 255,protocol = icmp,
         checksum = good,
         src = <<192,0,2,11>>,
         dst = <<192,0,2,1>>,
         options = <<>>},
     {bin,<<184,185,186,187,188,189,190,191,192,193,194,195,
            196,197,198,199,200,201,202,203,204,205,206,207,
            208,209,210,211,212,213,214,215,0,0,0,0,0,0,0,0>>}].

ipv6_frag_payload() ->
    <<104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159>>.

ipv6_frag_bin() ->
    Payload = ipv6_frag_payload(),
    <<0,3,71,140,161,179,26,249,192,230,163,71,134,221,96,0,0,0,1,64,44,64,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,9,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,58,0,14,112,133,47,74,97, Payload/bytes>>.

ipv6_frag_term() ->
    Payload = ipv6_frag_payload(),
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<26,249,192,230,163,71>>,
            type = ipv6},
     #ipv6{version = 6,traffic_class = 0,flow_label = 0,
           payload_length = 320,next_header = ipv6_frag,hop_limit = 64,
           src = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,9>>,
           dst = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>},
     #ipv6_frag{next_header = icmpv6,fragment_offset = 462,
                more = 0,identification = 2234468961},
     {bin, Payload}].

llc_bin() ->
    <<1,128,194,0,0,0,70,106,72,87,196,47,0,38,66,66,3,0,0,0,0,0,
      128,0,70,106,72,87,196,47,0,30,132,128,128,0,70,106,72,87,196,
      47,128,1,1,0,20,0,2,0,15,0
      % padding
      ,0,0,0,0,0,0,0,0>>.

llc_term() ->
    [#ether{dst = <<1,128,194,0,0,0>>,
            src = <<70,106,72,87,196,47>>,type = llc},
     #llc{dsap = stp,ssap = stp,control = #llc_control_u{m = 0,pf = 0}},
     {bin,<<0,0,0,0,0,128,0,70,106,72,87,196,47,0,30,132,128,
            128,0,70,106,72,87,196,47,128,1,1,0,20,0,2,0,15,0>>}].

snap_bin() ->
    <<0,0,0,0,0,0,0,3,71,140,161,179,0,48,170,170,3,0,0,0,8,0,
      69,0,0,40,0,0,0,0,255,6,189,205,127,0,0,1,127,0,0,1,11,
      164,39,15,0,0,0,0,0,0,0,0,80,0,0,0,127,47,0,0>>.

snap_term() ->
    [#ether{dst = <<0,0,0,0,0,0>>,
            src = <<0,3,71,140,161,179>>,
            type = llc},
     #llc{dsap = snap,ssap = snap,
          control = #llc_control_u{m = 0,pf = 0}},
     #snap{protocol_id = 0,type = ip},
     #ip{version = 4,ihl = 5,tos = 0,total_length = 40,id = 0,
         df = 0,mf = 0,offset = 0,ttl = 255,protocol = tcp,
         checksum = good,
         src = <<127,0,0,1>>,
         dst = <<127,0,0,1>>,
         options = <<>>},
     #tcp{src_port = 2980,dst_port = 9999,seqno = 0,ackno = 0,
          data_offset = 5,urg = 0,ack = 0,psh = 0,rst = 0,syn = 0,
          fin = 0,window = 0,checksum = good,urgent_pointer = 0,
          options = []}].

remove_pad(Packet) ->
    lists:keydelete(bin, 1, Packet).

tcp_decode_test() ->
    ?assertEqual(tcp_term(), aloha_packet:decode_packet(tcp_bin())).

tcp_encode_test() ->
    ?assertEqual(tcp_bin(), aloha_packet:encode_packet(tcp_term())).

tcp2_decode_test() ->
    ?assertEqual(tcp_term2(), aloha_packet:decode_packet(tcp_bin2())).

tcp2_encode_test() ->
    ?assertEqual(tcp_bin2(), aloha_packet:encode_packet(tcp_term2())).

tcp3_decode_test() ->
    ?assertEqual(tcp_term3(), aloha_packet:decode_packet(tcp_bin3())).

tcp3_encode_test() ->
    ?assertEqual(tcp_bin3(), aloha_packet:encode_packet(tcp_term3())).

arp_decode_test() ->
    ?assertEqual(arp_term(), aloha_packet:decode_packet(arp_bin())).

arp_encode_test() ->
    ?assertEqual(arp_bin(), aloha_packet:encode_packet(arp_term())).

icmpv6_decode_test() ->
    ?assertEqual(icmpv6_term(), aloha_packet:decode_packet(icmpv6_bin())).

icmpv6_encode_test() ->
    ?assertEqual(icmpv6_bin(), aloha_packet:encode_packet(icmpv6_term())).

neighbor_solicitation_decode_test() ->
    ?assertEqual(neighbor_solicitation_term(),
                 aloha_packet:decode_packet(neighbor_solicitation_bin())).

neighbor_solicitation_encode_test() ->
    ?assertEqual(neighbor_solicitation_bin(),
                 aloha_packet:encode_packet(neighbor_solicitation_term())).

neighbor_advertisement_decode_test() ->
    ?assertEqual(neighbor_advertisement_term(),
                 aloha_packet:decode_packet(neighbor_advertisement_bin())).

neighbor_advertisement_encode_test() ->
    ?assertEqual(neighbor_advertisement_bin(),
                 aloha_packet:encode_packet(neighbor_advertisement_term())).

icmp_decode_test() ->
    ?assertEqual(icmp_term(), aloha_packet:decode_packet(icmp_bin())).

icmp_encode_test() ->
    ?assertEqual(icmp_bin(), aloha_packet:encode_packet(icmp_term())).

ip_frag_decode_test() ->
    ?assertEqual(ip_frag_term(), aloha_packet:decode_packet(ip_frag_bin())).

ip_frag_encode_test() ->
    ?assertEqual(ip_frag_bin(), aloha_packet:encode_packet(ip_frag_term())).

ipv6_frag_decode_test() ->
    ?assertEqual(ipv6_frag_term(), aloha_packet:decode_packet(ipv6_frag_bin())).

ipv6_frag_encode_test() ->
    ?assertEqual(ipv6_frag_bin(), aloha_packet:encode_packet(ipv6_frag_term())).

ether_pad_test() ->
    ?assertEqual(60, byte_size(arp_bin())),
    ?assertEqual(arp_bin(), aloha_packet:encode_packet(remove_pad(arp_term()))).

llc_decode_test() ->
    ?assertEqual(60, byte_size(llc_bin())),
    ?assertEqual(llc_term(), aloha_packet:decode_packet(llc_bin())).

llc_encode_test() ->
    ?assertEqual(llc_bin(), aloha_packet:encode_packet(llc_term())).

snap_decode_test() ->
    ?assertEqual(snap_term(), aloha_packet:decode_packet(snap_bin())).

snap_encode_test() ->
    ?assertEqual(snap_bin(), aloha_packet:encode_packet(snap_term())).
