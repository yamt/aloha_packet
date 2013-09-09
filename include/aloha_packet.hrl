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

-type flag() :: 0 | 1.
-type u8() :: 0..16#ff.
-type u16() :: 0..16#ffff.
-type u32() :: 0..16#ffffffff.
-type ether_address() :: <<_:48>>.
-type ether_type() :: atom() | u8().
-type ip_address() :: <<_:32>>.
-type ipv6_address() :: <<_:128>>.
-type ip_proto() :: atom() | u8().
-type ip_port() :: u16().
-type tcp_seq() :: u32().
-type icmp_type() :: atom() | u8().
-type checksum16() :: u16 | good | bad | unknown.
-type plist() :: [atom() | tuple()].

-record(ether, {
    dst :: ether_address(),
    src :: ether_address(),
    type :: ether_type()}).
-record(arp, {hrd = 1, pro = ip, hln = 6, pln = 4, op, sha, spa, tha, tpa}).
-record(revarp, {hrd = 1, pro = ip, hln = 6, pln = 4, op, sha, spa, tha, tpa}).
-record(ip, {
    version = 4 :: 0..15,
    ihl :: 0..15,
    tos = 0 :: u8(),
    total_length :: u16(),
    id = 0 :: u16(),
    df = 0 :: flag(),
    mf = 0 :: flag(),
    offset = 0 :: 0..8191,
    ttl = 255 :: u8(),
    protocol :: ip_proto(),
    checksum :: checksum16(),
    src :: ip_address(), 
    dst :: ip_address(),
    options = <<>> :: binary()}).
-record(ipv6, {
    version = 6 :: 0..15,
    traffic_class = 0 :: u8(),
    flow_label = 0 :: 0..1048575,
    payload_length :: u16(),
    next_header :: ip_proto(),
    hop_limit = 255 :: u8(),
    src :: ipv6_address(),
    dst :: ipv6_address()}).
-record(ipv6_frag, {
    next_header :: u8(),
    fragment_offset :: 0..(1 bsl 13 - 1),
    more :: flag(),
    identification :: u32()}).
-record(icmp, {
    type :: icmp_type(),
    code = 0 :: u8(),
    checksum :: checksum16(),
    data :: binary()}).
-record(icmpv6, {
    type :: icmp_type(),
    code = 0 :: u8(),
    checksum :: checksum16(),
    data :: binary() | tuple()}).
-record(neighbor_solicitation, {
    target_address :: ipv6_address(),
    options = [] :: plist()}).
-record(neighbor_advertisement, {
    router :: flag(),
    solicited :: flag(),
    override :: flag(),
    target_address :: ipv6_address(),
    options = [] :: plist()}).
-record(tcp, {
    src_port :: ip_port(),
    dst_port :: ip_port(),
    seqno = 0 :: tcp_seq(),
    ackno = 0 :: tcp_seq(),
    data_offset = 0 :: 0..15,
    urg = 0 :: flag(),
    ack = 0 :: flag(),
    psh = 0 :: flag(),
    rst = 0 :: flag(),
    syn = 0 :: flag(),
    fin = 0 :: flag(),
    window = 0 :: u16(),
    checksum :: checksum16(),
    urgent_pointer = 0 :: u16(),
    options = [] :: binary() | plist()}).
