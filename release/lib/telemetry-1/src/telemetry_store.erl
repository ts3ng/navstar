%%%-------------------------------------------------------------------
%%% @author Tyler Neely
%%% @copyright (C) 2016, Mesosphere
%%% @doc
%%%
%%% @end
%%% Created : 2. Feb 2016 11:44 PM
%%%-------------------------------------------------------------------

-module(telemetry_store).
-behaviour(gen_server).

%% API
-export([start_link/0,
  submit/4,
  snapshot/0,
  reap/0,
  merge/1,
  add_gauge_func/2,
  remove_gauge_func/1
  ]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-include("telemetry.hrl").

-define(SERVER, ?MODULE).

-record(store, {
  metrics = #metrics{},
  metric_funs = maps:new()
  }).
-type state() :: #store{}.


%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Submit a metric to the store for aggregation.
%% @end
%%--------------------------------------------------------------------
-spec(submit(Name :: metric_name(), Time :: integer(), Type :: term(), Value :: term()) -> ok | {error, atom()}).
submit(Name, Time, Type, Value) ->
  gen_server:cast(?SERVER, {submit, Name, Time, Type, Value}).

%%--------------------------------------------------------------------
%% @doc
%% Get a snapshot of current metrics.
%% @end
%%--------------------------------------------------------------------
-spec(snapshot() -> #metrics{}).
snapshot() ->
  case ets:lookup(snapcache, last_snap) of
    [{last_snap, Cached}] ->
      lager:debug("returning cached snapshot"),
      Cached;
    _ ->
      lager:debug("returning generated snapshot"),
      gen_server:call(?SERVER, snapshot)
  end.

%%--------------------------------------------------------------------
%% @doc
%% For all times which have had metrics submitted in the last interval,
%% collect the counters and histogram exports.
%% @end
%%--------------------------------------------------------------------
-spec(reap() -> #metrics{}).
reap() ->
  gen_server:call(?SERVER, reap).

%%--------------------------------------------------------------------
%% @doc
%% Take counters and histograms and merge them with our state.
%% @end
%%--------------------------------------------------------------------
-spec(merge(Metrics :: #metrics{}) -> ok | {error, atom()}).
merge(Metrics) ->
  gen_server:cast(?SERVER, {merge, Metrics}).

%%--------------------------------------------------------------------
%% @doc
%% Register a fun of zero arity that returns a numerical value to be
%% called upon the creation of any metrics snapshot.
%% @end
%%--------------------------------------------------------------------
-spec(add_gauge_func(string(), fun()) -> ok | {error, atom()}).
add_gauge_func(Name, Fun) ->
  gen_server:call(?SERVER, {add_gauge_func, Name, Fun}).

%%--------------------------------------------------------------------
%% @doc
%% Remove a metrics function previously registered using add_gauge_func.
%% @end
%%--------------------------------------------------------------------
-spec(remove_gauge_func(string()) -> ok).
remove_gauge_func(Name) ->
  gen_server:call(?SERVER, {remove_gauge_func, Name}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(term()) ->
  {ok, State :: #store{}} | {ok, State :: #store{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([]) ->
  snapcache = ets:new(snapcache, [named_table, set, {read_concurrency, true}]),
  {ok, #store{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
  State :: state()) ->
  {reply, Reply :: #metrics{}, NewState :: state()} |
  {reply, Reply :: #metrics{}, NewState :: state(), timeout() | hibernate} |
  {noreply, NewState :: #store{}} |
  {noreply, NewState :: #store{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: state()} |
  {stop, Reason :: term(), NewState :: state()}).
handle_call(reap, _From, State) ->
  {Reply, NewState} = handle_reap(State),
  {reply, Reply, NewState};

handle_call(snapshot, _From, State = #store{metrics = Metrics}) ->
  ReapedState = export_metrics(Metrics),
  {reply, ReapedState, State};

handle_call({add_gauge_func, Name, Fun}, _From, State = #store{metric_funs = MetricFuns}) ->
  NewMetricFuns = maps:put(Name, Fun, MetricFuns),
  NewState = State#store{metric_funs = NewMetricFuns},
  {reply, ok, NewState};

handle_call({remove_gauge_func, Name}, _From, State = #store{metric_funs = MetricFuns}) ->
  NewMetricFuns = maps:remove(Name, MetricFuns),
  NewState = State#store{metric_funs = NewMetricFuns},
  {reply, ok, NewState};

handle_call(Request, _From, State) ->
  lager:warning("got unknown request in telemetry_store handle_call: ~p", [Request]),
  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: state()) ->
  {noreply, NewState :: state()} |
  {noreply, NewState :: state(), timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: state()}).
handle_cast({submit, Name, Time, histogram, Value}, State) ->
  NewState = handle_submit_histogram(Name, Time, Value, State),
  {noreply, NewState};
handle_cast({merge, Metrics}, State) ->
  NewState = handle_merge(Metrics, State),
  {noreply, NewState};
handle_cast({submit, Name, Time, counter, Value}, State) ->
  NewState = handle_submit_counter(Name, Time, Value, State),
  {noreply, NewState}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #metrics{}) ->
  {noreply, NewState :: #metrics{}} |
  {noreply, NewState :: #metrics{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #metrics{}}).
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
  State :: state()) -> term()).
terminate(_Reason, _State = #store{}) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: state(),
  Extra :: term()) ->
  {ok, NewState :: state()} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Takes an orddict of {Time, Name} -> histogram exported binaries,
%% and merges it with an orddict of {Time, Name} -> histogram
%% local instances.
%% @end
%%--------------------------------------------------------------------
merge_histos(TimeToHistos1, TimeToHistos2) ->
  MergeFunc = fun (_K, Histo1, Histo2) ->
                  telemetry_histo:merge(Histo1, Histo2)
              end,
  orddict:merge(MergeFunc, TimeToHistos1, TimeToHistos2).


merge_counters(TimeToCounters1, TimeToCounters2) ->
  MergeFunc = fun(_K, Counter1, Counter2) ->
                  Counter1 + Counter2
              end,
  orddict:merge(MergeFunc, TimeToCounters1, TimeToCounters2).


record_gauge_funcs(Metrics = #metrics{time_to_counters = TimeToCounters,
                                      dirty_counters = DirtyCounters},
                   MetricFuns) ->
  Now = os:system_time(seconds),
  NormalizedTime = Now - (round(Now) rem telemetry_config:interval_seconds()),

  {RetCounters2, DirtyCounters2} = maps:fold(fun (Name, Fun, {AccIn, AccDirtyIn}) ->
                                                 Value = Fun(),
                                                 AccCounter = orddict:store({NormalizedTime, Name}, Value, AccIn),
                                                 AccDirty = sets:add_element({NormalizedTime, Name}, AccDirtyIn),
                                                 {AccCounter, AccDirty}
                                             end, {TimeToCounters, DirtyCounters}, MetricFuns),

  Metrics#metrics{time_to_counters = RetCounters2,
                  dirty_counters = DirtyCounters2}.


-spec(export_metrics(#metrics{}) -> #metrics{}).
export_metrics(#metrics{time_to_histos = TimeToHistos,
                        time_to_counters = TimeToCounters,
                        dirty_histos = DirtyHistos,
                        dirty_counters = DirtyCounters}) ->

  ExportedMetrics = #metrics{time_to_histos = TimeToHistos,
                             time_to_counters = TimeToCounters,
                             dirty_histos = DirtyHistos,
                             dirty_counters = DirtyCounters},
  lager:debug("populating the snapcache with metrics"),
  true = ets:insert(snapcache, {last_snap, ExportedMetrics}),
  ExportedMetrics.



submit_to_opentsdb(#metrics{time_to_histos = TimeToHistos,
                            time_to_counters = TimeToCounters}) ->
  %% TODO(tyler) rip out this filthy hack
  Now = os:system_time(seconds),
  NormalizedTime = Now - (round(Now) rem telemetry_config:interval_seconds()),
  Gate = NormalizedTime - telemetry_config:interval_seconds() + 1,

  Counters = orddict:filter(fun (K, _V) ->
                                K > Gate
                            end, TimeToCounters),
  Histos = orddict:filter(fun (K, _V) ->
                              K > Gate
                          end, TimeToHistos),
  Summary = telemetry:metrics_to_summary(#metrics{time_to_histos = Histos,
                                                  time_to_counters = Counters}),
  #{counters := CounterSummary, histograms := HistoSummary} = Summary,
  submit_counters_to_opentsdb(CounterSummary),
  submit_histos_to_opentsdb(HistoSummary),

  ok.


submit_counters_to_opentsdb(Summary) ->
  Metrics = maps:fold(fun (#name_tags{name = Name, tags = Tags}, TimeValue, AccIn) ->
                          maps:fold(fun (Time, Value, SubAccIn) ->
                                        [{Name, Time, Value, Tags} | SubAccIn]
                                    end, AccIn, TimeValue)
                     end, [], Summary),
  gen_opentsdb:put_metric_batch(Metrics).


submit_histos_to_opentsdb(Summary) ->
  Metrics = maps:fold(fun (#name_tags{name = Name, tags = Tags}, TimeValue, AccIn) ->
                          maps:fold(fun (Time, HistoSummary, SubAccIn) ->
                                        maps:fold(fun (SubHistoName, Value, SubSubAccIn) ->
                                                      [{Name, Time, Value, Tags#{histo => SubHistoName}} | SubSubAccIn]
                                                  end, SubAccIn, HistoSummary)
                                    end, AccIn, TimeValue)
                      end, [], Summary),
  gen_opentsdb:put_metric_batch(Metrics).

-spec(handle_reap(State :: state()) -> {Reply :: #metrics{}, NewState :: state()}).
handle_reap(State = #store{metrics = Metrics, metric_funs = MetricFuns}) ->
    %% record function gauges
    Metrics2 = record_gauge_funcs(Metrics, MetricFuns),

    #metrics{time_to_histos = TimeToHistos,
        time_to_counters = TimeToCounters} = Metrics2,

    %% Create a snapshot of current metrics.
    ReapedState = export_metrics(Metrics2),

    %% Prune metrics that we should shed.
    Now = os:system_time(seconds),

    CutoffTime = Now - (telemetry_config:interval_seconds() *
        telemetry_config:max_intervals()),

    TimeGate = fun ({Time, _Name}, _V) ->
        Time >= CutoffTime
               end,
    TimeToHistos2 = orddict:filter(TimeGate, TimeToHistos),
    TimeToCounters2 = orddict:filter(TimeGate, TimeToCounters),

    %% Only nodes in aggregator mode should retain non-partial metrics.
    IsAggregator = telemetry_config:is_aggregator(),
    RetMetrics = case IsAggregator of
                     true -> #metrics{time_to_histos = TimeToHistos2,
                         time_to_counters = TimeToCounters2};
                     false -> #metrics{}
                 end,
    RetState = State#store{metrics = RetMetrics, metric_funs = MetricFuns},
    {ReapedState, RetState}.


-spec(handle_submit_histogram(Name :: term(), Time :: term(), Value :: term(), State :: state()) ->
    NewState :: state()).
handle_submit_histogram(Name, Time, Value, State = #store{metrics = Metrics}) ->
    #metrics{time_to_histos = TimeToHistos,
        dirty_histos = DirtyHistos} = Metrics,
    NormalizedTime = Time - (round(Time) rem telemetry_config:interval_seconds()),
    TimeToHistos2 = case orddict:is_key({NormalizedTime, Name}, TimeToHistos) of
                        true ->
                            TimeToHistos;
                        false ->
                            Histo = telemetry_histo:new(),
                            orddict:store({NormalizedTime, Name}, Histo, TimeToHistos)
                    end,

    TimeToHistos3 = orddict:update({NormalizedTime, Name},
        fun(Histo) ->
            telemetry_histo:record(Histo, Value)
        end, TimeToHistos2),

    DirtyHistos2 = sets:add_element({NormalizedTime, Name}, DirtyHistos),

    RetMetrics = Metrics#metrics{time_to_histos = TimeToHistos3,
        dirty_histos = DirtyHistos2},

    State#store{metrics = RetMetrics}.

-spec(handle_submit_counter(Name :: term(), Time :: term(), Value :: term(), State :: state()) ->
    NewState :: state()).
handle_submit_counter(Name, Time, Value, State = #store{metrics = Metrics}) ->
    #metrics{time_to_counters = TimeToCounters,
        dirty_counters = DirtyCounters} = Metrics,

    NormalizedTime = Time - (round(Time) rem telemetry_config:interval_seconds()),

    TimeToCounters2 = orddict:update_counter({NormalizedTime, Name}, Value, TimeToCounters),

    DirtyCounters2 = sets:add_element({NormalizedTime, Name}, DirtyCounters),

    RetMetrics = Metrics#metrics{time_to_counters = TimeToCounters2,
        dirty_counters = DirtyCounters2},

    State#store{metrics = RetMetrics}.


-spec(handle_merge(Metrics :: #metrics{}, State :: state()) -> NewState :: state()).
handle_merge(#metrics{time_to_histos = TimeToHistosIn,
    time_to_counters = TimeToCountersIn,
    dirty_histos = DirtyHistosIn,
    dirty_counters = DirtyCountersIn},
    _State = #store{metrics = Metrics, metric_funs = MetricFuns}) ->

    #metrics{time_to_histos = TimeToHistos,
        time_to_counters = TimeToCounters,
        dirty_histos = DirtyHistos,
        dirty_counters = DirtyCounters} = Metrics,
    MergedDirtyHistos = sets:union(DirtyHistosIn, DirtyHistos),
    MergedDirtyCounters = sets:union(DirtyCountersIn, DirtyCounters),
    MergedCounters = merge_counters(TimeToCountersIn, TimeToCounters),
    MergedHistos = merge_histos(TimeToHistosIn, TimeToHistos),
    MergedMetrics = #metrics{time_to_histos = MergedHistos,
        time_to_counters = MergedCounters,
        dirty_histos = MergedDirtyHistos,
        dirty_counters = MergedDirtyCounters},
    maybe_push_to_opentsdb(MergedMetrics, DirtyHistosIn, DirtyCountersIn),
    #store{metrics = MergedMetrics, metric_funs = MetricFuns}.

maybe_push_to_opentsdb(MergedMetrics, DirtyHistosIn, DirtyCountersIn) ->
    case telemetry_config:opentsdb_endpoint() of
        false -> ok;
        _ ->
            submit_to_opentsdb(MergedMetrics#metrics{dirty_histos = DirtyHistosIn,
                dirty_counters = DirtyCountersIn}),
            ok
    end.
