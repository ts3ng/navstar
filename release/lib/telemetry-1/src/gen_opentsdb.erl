-module(gen_opentsdb).
-behaviour(gen_server).

%% API
-export([start_link/0, put_metric_batch/1, put_metric/2, put_metric/3, put_metric_/2, put_metric_/3, q/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TCP_DEFAULT, [binary, {packet, 0}]).

-record(otsdb, {
  host = telemetry_config:opentsdb_endpoint(),
  port = 4242
  }).

%% API
start_link() ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

put_metric_batch(Metrics) ->
  gen_server:call(?MODULE, {put_batch, Metrics}).

put_metric(Name, Amount) ->
  put_metric(Name, Amount, []).

put_metric(Name, Amount, Tags) ->
  gen_server:call(?MODULE, {put, Name, round(Amount), Tags}).

put_metric_(Name, Amount) ->
  put_metric(Name, Amount, []).

put_metric_(Name, Amount, Tags) ->
  gen_server:cast(?MODULE, {put, Name, Amount, Tags}).

%% TODO add query HTTP API here, return decoded json.
q(Cmd) ->
  {ok, Cmd}.

%% gen_server-y goodness
init([]) ->
	{ok, #otsdb{}}.

handle_call({put, Metric, Amount, Tags}, _From, State) ->
  Reply = execute(State, {put, Metric, Amount, Tags}),
  {reply, Reply, State};
handle_call({put_batch, Metrics}, _From, State) ->
  Reply = execute(State, {put_batch, Metrics}),
  {reply, Reply, State};
handle_call(_Request, _From, State) ->
	{reply, ok, State}.

handle_cast({put, Metric, Amount, Tags}, State) ->
  execute(State, {put, Metric, Amount, Tags}),
  {noreply, State};
handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%% Internal functions
unix_timestamp() ->
  round(os:system_time() / 1000000000).

execute(#otsdb{host=false}, _Action) ->
  {error, no_opentsdb_endpoint_configured};

execute(#otsdb{host=Host, port=Port}, _Action = {put, Metric, Amount, Tags}) ->
      case convert_amount(Amount) of
        {ok, SafeAmount} ->
          Time = list_to_binary(integer_to_list(unix_timestamp())),
          Msg = opentsdb_fmt(Metric, Time, SafeAmount, Tags),
          send(Host, Port, Msg);
        _ -> {error, invalid_amount}
      end;
execute(#otsdb{host=Host, port=Port}, _Action = {put_batch, Metrics}) ->
      Msg = lists:map(fun ({Name, Time, Amount, Tags}) ->
                          case convert_amount(Amount) of
                            {ok, SafeAmount} ->
                              BinTime = list_to_binary(integer_to_list(Time)),
                              opentsdb_fmt(Name, BinTime, SafeAmount, Tags);
                            _ ->
                              []
                          end
                      end, Metrics),
      send(Host, Port, Msg).

send(Host, Port, Msg) ->
  {ok, Sock} = gen_tcp:connect(Host, Port, ?TCP_DEFAULT),
  Reply = gen_tcp:send(Sock, Msg),
  ok = gen_tcp:close(Sock),
  Reply.

opentsdb_fmt(Metric, Time, Amount, Tags) ->
  SafeMetric = sanitize_to_binary(Metric),
  SafeTags = format_tags(Tags),
  <<$p,$u,$t,$\s, SafeMetric/binary, $\s, Time/binary, $\s, Amount/binary, $\s, SafeTags/binary, $\n>>.

convert_amount(Amount) ->
  NewAmount = case Amount of
    A when is_integer(A) -> {ok, list_to_binary(integer_to_list(A))};
    A when is_float(A) -> {ok, list_to_binary(float_to_list(A))};
    A when is_list(A) -> {ok, list_to_binary(A)};
    A when is_binary(A) -> {ok, A};
    _ -> {error, unknown_type}
  end,
  NewAmount.

sanitize_to_binary(V) ->
  FmtV = io_lib:format("~p", [V]),
  SanitizedV = re:replace(FmtV, "[^A-Za-z0-9./\\-_]", "", [global, {return, list}]),
  list_to_binary(SanitizedV).

format_tags(Tags) ->
  TagList = maps:to_list(Tags),
  BinaryTagList = lists:map(fun({T, V}) ->
                                {sanitize_to_binary(T), sanitize_to_binary(V)}
                            end, TagList),
  lists:foldl(fun(E, A) ->
    <<A/binary, E/binary>>
  end, <<>>, [<<K/binary, $=, V/binary, $\s>> || {K, V} <- BinaryTagList]).
