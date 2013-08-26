aloha_packet
============

This is a packet decoder/encoder written in Erlang.

[![Build Status](https://travis-ci.org/yamt/aloha_packet.png?branch=master)](https://travis-ci.org/yamt/aloha_packet)

Example
=======

    Erlang R16B01 (erts-5.10.2) [source] [64-bit] [smp:8:8] [async-threads:10] [hipe] [kernel-poll:false] [dtrace]

    Eshell V5.10.2  (abort with ^G)
    1> rr(aloha_packet).
    [arp,ether,icmp,icmpv6,ip,ipv6,neighbor_advertisement,
     neighbor_solicitation,revarp,tcp]
    2> B = <<0,3,71,140,161,179,142,17,145,26,179,75,134,221,96,11,253,148,0,27,6,64,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,255,149,39,15,86,177,116,116,0,0,0,102,80,24,129,96,164,221,0,0,97,108,111,104,97,13,10>>.
    <<0,3,71,140,161,179,142,17,145,26,179,75,134,221,96,11,
      253,148,0,27,6,64,32,1,13,184,0,0,0,...>>
    3> T = aloha_packet:decode_packet(B).
    [#ether{dst = <<0,3,71,140,161,179>>,
            src = <<142,17,145,26,179,75>>,
            type = ipv6},
     #ipv6{version = 6,traffic_class = 0,flow_label = 785812,
           payload_length = 27,next_header = tcp,hop_limit = 64,
           src = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2>>,
           dst = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>},
     #tcp{src_port = 65429,dst_port = 9999,seqno = 1454470260,
          ackno = 102,data_offset = 5,urg = 0,ack = 1,psh = 1,rst = 0,
          syn = 0,fin = 0,window = 33120,checksum = good,
          urgent_pointer = 0,options = []},
     {bin,<<"aloha\r\n">>}]
    4> B = aloha_packet:encode_packet(T).
    <<0,3,71,140,161,179,142,17,145,26,179,75,134,221,96,11,
      253,148,0,27,6,64,32,1,13,184,0,0,0,...>>
    5> 
