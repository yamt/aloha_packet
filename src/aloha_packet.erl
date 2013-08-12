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

-module(aloha_packet).
-export([encode_packet/1]).
-export([decode_packet/1, decode/2]).

-include("aloha_packet.hrl").

encode_packet(List) ->
    encode_packet(lists:reverse(List), <<>>).

encode_packet([], Acc) ->
    Acc;
encode_packet([H|Rest], Acc) ->
    encode_packet(Rest, encode(H, Rest, Acc)).

decode_packet(Data) ->
    decode_packet(ether, Data, []).

decode_packet(_Type, <<>>, Acc) ->
    lists:reverse(Acc);
decode_packet(Type, Data, Acc) ->
    {Rec, NextType, Rest} = decode(Type, Data),
    decode_packet(NextType, Rest, [Rec|Acc]).

decode(ether, Data) ->
    <<Dst:6/bytes, Src:6/bytes, TypeInt:16, Rest/bytes>> = Data,
    Type = to_atom(ethertype, TypeInt),
    {#ether{dst=Dst, src=Src, type=Type}, Type, Rest};
decode(arp, Data) ->
    decode_arp(Data);
decode(revarp, Data) ->
    % compatible with arp
    Result = decode_arp(Data),
    setelement(1, Result, revarp);
decode(ip, Data) ->
    <<Version:4, IHL:4, TOS:8, TotalLength:16,
      Id:16, _:1, DF:1, MF:1, Offset:13,
      TTL:8, ProtocolInt:8, Checksum:16,
      Src:4/bytes, Dst:4/bytes, Rest/bytes>> = Data,
    OptLen = (IHL * 4) - 20,
    DataLen = TotalLength - OptLen - 20,
    <<Options:OptLen/bytes, Rest2:DataLen/bytes, _/bytes>> = Rest,
    Protocol = to_atom(ip_proto, ProtocolInt),
    {#ip{version=Version, ihl=IHL, tos=TOS, total_length=TotalLength,
     id=Id, df=DF, mf=MF, offset=Offset, ttl=TTL, protocol=Protocol,
     checksum=Checksum, src=Src, dst=Dst, options=Options}, Protocol, Rest2};
decode(icmp, Data) ->
    <<Type:8, Code:8, Checksum:16, Rest/bytes>> = Data,
    {#icmp{type=Type, code=Code, checksum=Checksum, data=Rest}, unknown, <<>>};
decode(ipv6, Data) ->
    <<Version:4, TrafficClass:8, FlowLabel:20,
      PayloadLength:16, NextHeaderInt:8, HopLimit:8,
      Src:16/bytes, Dst:16/bytes, Rest/bytes>> = Data,
    NextHeader = to_atom(ip_proto, NextHeaderInt),
    {#ipv6{version=Version, traffic_class=TrafficClass,
     flow_label=FlowLabel, payload_length=PayloadLength,
     next_header=NextHeader, hop_limit=HopLimit, src=Src, dst=Dst},
     NextHeader, Rest};
decode(tcp, Data) ->
    <<SrcPort:16, DstPort:16,
      SeqNo:32,
      AckNo:32,
      DataOffset:4, _:6, URG:1, ACK:1, PSH:1, RST:1, SYN:1, FIN:1, Window:16,
      Checksum:16, UrgentPointer:16,
      Rest/bytes>> = Data,
    OptLen = (DataOffset - 5) * 4,
    <<Options:OptLen/bytes, Rest2/bytes>> = Rest,
    {#tcp{src_port=SrcPort, dst_port=DstPort,
               seqno=SeqNo, ackno=AckNo, data_offset=DataOffset,
               urg=URG, ack=ACK, psh=PSH, rst=RST, syn=SYN, fin=FIN,
               window=Window, checksum=Checksum, urgent_pointer=UrgentPointer,
               options=Options}, bin, Rest2};
decode(Type, Data) ->
    {{Type, Data}, unknown, <<>>}.

decode_arp(Data) ->
    <<Hrd:16, Pro:16, Hln:8, Pln:8, Op:16, Rest/bytes>> = Data,
    <<Sha:Hln/bytes, Spa:Pln/bytes, Tha:Hln/bytes, Tpa:Pln/bytes,
      Rest2/bytes>> = Rest,
    {#arp{hrd=Hrd, pro=to_atom(ethertype, Pro), hln=Hln, pln=Pln, op=Op,
      sha=Sha, spa=Spa, tha=Tha, tpa=Tpa}, unknown, Rest2}.

encode(#ether{dst=Dst, src=Src, type=Type}, _Stack, Rest) ->
    TypeInt = to_int(ethertype, Type),
    Bin = <<Dst:6/bytes, Src:6/bytes, TypeInt:16, Rest/bytes>>,
    Size = size(Bin),
    Pad = max(60 - Size, 0),
    <<Bin/binary, 0:Pad/unit:8>>;
encode(#ip{version=Version, ihl=IHL, tos=TOS, total_length=_TotalLength,
     id=Id, df=DF, mf=MF, offset=Offset, ttl=TTL, protocol=Protocol,
     checksum=_Checksum, src=Src, dst=Dst, options=Options}, _Stack, Rest) ->
    ProtocolInt = to_int(ip_proto, Protocol),
    OptLen = size(Options),
    OptPadLen = (-OptLen) band 3,
    TotalLength = 20 + OptLen + OptPadLen + size(Rest),
    Checksum = checksum(<<Version:4, IHL:4, TOS:8, TotalLength:16,
      Id:16, 0:1, DF:1, MF:1, Offset:13,
      TTL:8, ProtocolInt:8, 0:16,
      Src:4/bytes, Dst:4/bytes, Options/bytes, 0:OptPadLen/unit:8>>),
    <<Version:4, IHL:4, TOS:8, TotalLength:16,
      Id:16, 0:1, DF:1, MF:1, Offset:13,
      TTL:8, ProtocolInt:8, Checksum:16,
      Src:4/bytes, Dst:4/bytes, Options/bytes, 0:OptPadLen/unit:8,
      Rest/bytes>>;
encode(#arp{hrd=Hrd, pro=Pro, hln=Hln, pln=Pln, op=Op,
       sha=Sha, spa=Spa, tha=Tha, tpa=Tpa}, _Stack, <<>>) ->
    ProInt = to_int(ethertype, Pro),
    <<Hrd:16, ProInt:16, Hln:8, Pln:8, Op:16,
      Sha:Hln/bytes, Spa:Pln/bytes, Tha:Hln/bytes, Tpa:Pln/bytes>>;
encode(#icmp{type=Type, code=Code, checksum=_Checksum, data=Data},
       _Stack, <<>>) ->
    Pkt = <<Type:8, Code:8, 0:16, Data/bytes>>,
    Checksum = checksum(Pkt),
    <<Type:8, Code:8, Checksum:16, Data/bytes>>;
encode(#tcp{src_port=SrcPort, dst_port=DstPort,
            seqno=SeqNo, ackno=AckNo, data_offset=_DataOffset,
            urg=URG, ack=ACK, psh=PSH, rst=RST, syn=SYN, fin=FIN,
            window=Window, checksum=_Checksum,
            urgent_pointer=UrgentPointer, options=Options}, Stack, Rest) ->
    [Ip|_] = Stack,
    OptLen = size(Options),
    OptPadLen = (-OptLen) band 3,
    DataOffset = (OptLen + OptPadLen) div 4 + 5,
    Phdr = phdr(Ip, DataOffset * 4 + size(Rest)),
    Hdr = <<SrcPort:16, DstPort:16, SeqNo:32, AckNo:32,
      DataOffset:4, 0:6, URG:1, ACK:1, PSH:1, RST:1, SYN:1, FIN:1, Window:16,
      0:16, UrgentPointer:16, Options:OptLen/bytes, 0:OptPadLen/unit:8>>,
    Checksum = checksum(<<Phdr/bytes, Hdr/bytes, Rest/bytes>>),
    <<SrcPort:16, DstPort:16, SeqNo:32, AckNo:32,
      DataOffset:4, 0:6, URG:1, ACK:1, PSH:1, RST:1, SYN:1, FIN:1, Window:16,
      Checksum:16, UrgentPointer:16, Options:OptLen/bytes, 0:OptPadLen/unit:8,
      Rest/bytes>>;
encode({bin, Bin}, _Stack, Rest) ->
    <<Bin/bytes, Rest/bytes>>;
encode(Bin, _Stack, Rest) when is_binary(Bin) ->
    <<Bin/bytes, Rest/bytes>>.

phdr(#ip{src=Src, dst=Dst, protocol=Proto}, Len) ->
    ProtoInt = to_int(ip_proto, Proto),
    <<Src:4/bytes, Dst:4/bytes,
      0:8, ProtoInt:8, Len:16>>.

checksum(Bin) ->
    checksum_fold(checksum_add(Bin, 0)).

checksum_add(<<>>, Acc) ->
    Acc;
checksum_add(<<Byte:8>>, Acc) ->
    checksum_add(<<>>, Acc + (Byte bsl 8));
checksum_add(<<Word:16, Rest/bytes>>, Acc) ->
    checksum_add(Rest, Acc + Word).

checksum_fold(Sum) when Sum =< 16#ffff ->
    16#ffff - Sum;
checksum_fold(Sum) ->
    checksum_fold((Sum band 16#ffff) + (Sum bsr 16)).

to_int(Type, Enum) ->
    try
        aloha_enum:to_int(Type, Enum)
    catch
        throw:bad_enum ->
            Enum
    end.

to_atom(Type, Enum) ->
    try
        aloha_enum:to_atom(Type, Enum)
    catch
        throw:bad_enum ->
            Enum
    end.
