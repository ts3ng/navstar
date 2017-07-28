%%%-------------------------------------------------------------------
%%% @author Anatoly Yakovenko
%%% @copyright (C) 2015, Mesosphere
%%% @doc
%%%
%%% @end
%%% Created : 03. Oct 2016 11:44 AM
%%%-------------------------------------------------------------------
-module(tcp_metrics_monitor).
-author("Anatoly Yakovenko").

-behaviour(gen_server).
-include_lib("gen_netlink/include/netlink.hrl").

-export([get_metrics/1]).
-export([start_link/0]).

-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
        family :: integer()
    }).

-spec(start_link() ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec(init(term()) ->
    {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |

    {stop, Reason :: term()} | ignore).
init([]) ->
    process_flag(trap_exit, true),
    {ok, Family} = get_family(),
    {ok, #state{family = Family}}.

-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
    {reply, Reply :: term(), NewState :: #state{}} |
    {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec(handle_cast(Request :: term(), State :: #state{}) ->
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_cast({get_metrics, Atom, Pid}, State = #state{family = Family}) ->
    Metrics = get_metrics_from_proc(Family),
    {Atom, Metrics} = erlang:send(Pid, {Atom, Metrics}),
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.

-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_info(_Info, State) ->
    {noreply, State}.

-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State = #state{}) ->
    ok.

-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
    {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


-spec(get_family() -> {ok, integer()} | {error, term() | string() | binary()}).
get_family() ->
    {ok, Socket} = procket:socket(netlink, dgram, ?NETLINK_GENERIC),
    Pid = 0,
    Seq = erlang:unique_integer([positive]),
    Flags = [ack, request],
    Payload = #getfamily{request = [{family_name, "tcp_metrics"}]},
    Msg = {netlink, ctrl, Flags, Seq, Pid, Payload},
    Data = netlink_codec:nl_enc(generic, Msg),
    SndRsp = procket:sendto(Socket, Data),
    RecvRsp = procket:recv(Socket, 4*1024),
    procket:close(Socket),
    ok = SndRsp,
    {ok, Rsp} = RecvRsp,
    Decoded = netlink_codec:nl_dec(?NETLINK_GENERIC, Rsp),
    [#netlink{seq = Seq, msg = {newfamily,_,_, Attrs}}] = Decoded,
    {family_id, Family} = lists:keyfind(family_id, 1, Attrs),
    {ok, Family}.

-spec(get_metrics(atom()) -> ok | {error, term()}).
get_metrics(Atom) -> gen_server:cast(?SERVER, {get_metrics, Atom, self()}).

-spec(get_metrics_from_socket(integer(), {ok, integer()} | {error, term()}) -> [term()]).
get_metrics_from_socket(Family, {ok, Socket}) ->
    Pid = 0,
    Seq = erlang:unique_integer([positive]),
    Flags = [?NLM_F_DUMP, request],
    Msg = {netlink, tcp_metrics, Flags, Seq, Pid, {get, 1, 0, []}},
    Data = netlink_codec:nl_enc(Family, Msg),
    SndRsp = procket:sendto(Socket, Data),
    RecvRsp = procket:recv(Socket, 64*1024),
    procket:close(Socket),
    ok = SndRsp,
    {ok, Rsp} = RecvRsp,
    netlink_codec:nl_dec(tcp_metrics, Rsp);

get_metrics_from_socket(_, _) -> [].

get_metrics_from_proc(Family) ->
    Opts = [{family, netlink},
            {protocol, ?NETLINK_GENERIC},
            {type,dgram}],
    Socket = procket:open(0, Opts),
    get_metrics_from_socket(Family, Socket).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

handle_bad_socket_test_() ->
    [?_assertEqual([], get_metrics_from_socket(1, {error, foobar}))].

normal_socket_test_() ->
    {ok, Family} = get_family(),
    {ok, Socket} = procket:socket(inet6, stream, tcp),
    SA = list_to_binary([procket:sockaddr_common(inet6, 128), <<0:16/integer-unsigned-big, 0:((128 - (2+2))*8)>>]),
    ok = procket:bind(Socket, SA),
    {Sz, RA} = procket:getsockname(Socket, SA),
    io:format("listen address ~p ~p\n", [Sz,RA]),
    ok = procket:listen(Socket, 1),
    {ok, Send} = procket:socket(inet6, stream, tcp),
    procket:connect(Send, RA),
    {ok, Recv} = procket:accept(Socket),
    Attrs = [{d_addr,{54,192,147,29}},
             {s_addr,{10,0,79,182}},
             {age_ms,806101408},
             {vals,[{rtt_us,47313},
                    {rtt_ms,47},
                    {rtt_var_us,23656},
                    {rtt_var_ms,23},
                    {cwnd,10}]}],
    Msg = [{netlink,tcp_metrics, [multi], 18,31595, {get,1,0,Attrs}}],
    Buf = netlink_codec:nl_enc(Family, Msg),
    io:format("message ~p\n", [Buf]),
    procket:sendto(Send, Buf),
    [?_assertEqual(Msg, get_metrics_from_socket(Family, {ok, Recv}))].

-endif.
