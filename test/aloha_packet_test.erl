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

tcp_decode_test() ->
    ?assertEqual(tcp_term(), aloha_packet:decode_packet(tcp_bin())).

tcp_encode_test() ->
    ?assertEqual(tcp_bin(), aloha_packet:encode_packet(tcp_term())).
