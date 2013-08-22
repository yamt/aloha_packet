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

-module(aloha_enum).
-compile({parse_transform, eenum}).

-enum({ethertype, [{ip, 16#0800},
                   {arp, 16#0806},
                   {revarp, 16#8035},
                   {ipv6, 16#86dd}]}).

-enum({ip_proto, [{icmp, 1},
                  {tcp, 6},
                  {udp, 17},
                  {icmpv6, 58}]}).

-enum({arp_op, [{request, 1},
                {reply, 2}]}).

-enum({icmp_type, [{echo_reply, 0},
                   {echo_request, 8}]}).

-enum({icmpv6_type, [{destination_unreachable, 1},
                     {packet_too_big, 2},
                     {time_exceed, 3},
                     {parameter_problem, 4},
                     {echo_request, 128},
                     {echo_reply, 129}]}).

-enum({tcp_option, [{eol, 0},
                    {noop, 1},
                    {mss, 2},
                    {wscale, 3},
                    {sack_permitted, 4},
                    {sack, 5},
                    {timestamp, 8}]}).
