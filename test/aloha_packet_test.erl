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

-include_lib("eunit/include/eunit.hrl").

tcp_bin() ->
    <<242,11,164,149,235,12,0,3,71,140,161,179,8,0,69,0,0,162,0,0,64,0,64,6,182,75,192,0,2,1,192,0,2,9,31,144,210,224,0,0,0,1,180,110,233,188,80,16,11,184,54,65,0,0,72,84,84,80,47,49,46,49,32,50,48,48,32,79,75,13,10,99,111,110,110,101,99,116,105,111,110,58,32,107,101,101,112,45,97,108,105,118,101,13,10,115,101,114,118,101,114,58,32,67,111,119,98,111,121,13,10,100,97,116,101,58,32,77,111,110,44,32,49,50,32,65,117,103,32,50,48,49,51,32,49,52,58,52,48,58,50,51,32,71,77,84,13,10,99,111,110,116,101,110,116,45,108,101,110,103,116,104,58,32,55,13,10,13,10,97,108,111,104,97,33,10>>.

tcp_term() ->
    [
        {ether,<<242,11,164,149,235,12>>,<<0,3,71,140,161,179>>,ip},
        {ip,4,5,0,162,0,1,0,0,64,tcp,46667,<<192,0,2,1>>,<<192,0,2,9>>,<<>>},
        {tcp,8080,53984,1,3027167676,5,0,1,0,0,0,0,3000,13889,0,<<>>},
        {bin,<<"HTTP/1.1 200 OK\r\nconnection: keep-alive\r\nserver: Cowboy\r\ndate: Mon, 12 Aug 2013 14:40:23 GMT\r\ncontent-length: 7\r\n\r\naloha!\n">>}].

arp_bin() ->
    <<242,11,164,149,235,12,0,3,71,140,161,179,8,6,0,1,8,0,6,4,0,2,0,3,71,140,161,179,192,0,2,1,242,11,164,149,235,12,192,0,2,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

arp_term() ->
    [{ether,<<242,11,164,149,235,12>>,<<0,3,71,140,161,179>>,arp},
     {arp,1,ip,6,4,2,
      <<0,3,71,140,161,179>>, <<192,0,2,1>>,
      <<242,11,164,149,235,12>>, <<192,0,2,9>>},
     {bin,<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}].

icmp_bin() ->
    <<0,3,71,140,161,179,242,11,164,149,235,12,8,0,69,0,0,84,220,4,0,0,255,1,91,153,192,0,2,9,192,0,2,1,8,0,97,173,21,237,0,1,159,59,12,0,0,0,0,0,175,21,52,17,0,0,0,0,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,0,0,0,0,0,0,0,0>>.

icmp_term() ->
    [{ether,<<0,3,71,140,161,179>>,<<242,11,164,149,235,12>>,ip},
     {ip,4,5,0,84,56324,0,0,0,255,icmp,23449,<<192,0,2,9>>,<<192,0,2,1>>,<<>>},
      {icmp,8,0,25005,
       <<21,237,0,1,159,59,12,0,0,0,0,0,175,21,52,17,0,0,0,0,16,17,18,19,20,
         21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,
         43,44,45,46,47,0,0,0,0,0,0,0,0>>}].

remove_pad(Packet) ->
    lists:keydelete(bin, 1, Packet).

tcp_decode_test() ->
    ?assertEqual(tcp_term(), aloha_packet:decode_packet(tcp_bin())).

tcp_encode_test() ->
    ?assertEqual(tcp_bin(), aloha_packet:encode_packet(tcp_term())).

arp_decode_test() ->
    ?assertEqual(arp_term(), aloha_packet:decode_packet(arp_bin())).

arp_encode_test() ->
    ?assertEqual(arp_bin(), aloha_packet:encode_packet(arp_term())).

icmp_decode_test() ->
    ?assertEqual(icmp_term(), aloha_packet:decode_packet(icmp_bin())).

icmp_encode_test() ->
    ?assertEqual(icmp_bin(), aloha_packet:encode_packet(icmp_term())).

ether_pad_test() ->
    ?assertEqual(arp_bin(), aloha_packet:encode_packet(remove_pad(arp_term()))).
