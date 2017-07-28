-type key() :: term().

-define(OLD_KV_TABLE, kv).
-define(KV_TABLE, kv2).

-record(kv, {
  key = erlang:error() :: key(),
  map = riak_dt_map:new() :: riak_dt_map:dt_map(),
  vclock = riak_dt_vclock:fresh()
}).

-record(kv2, {
  key = erlang:error() :: key(),
  map = riak_dt_map:new() :: riak_dt_map:dt_map(),
  vclock = riak_dt_vclock:fresh(),
  lclock = 0 :: non_neg_integer()  %% logical clock
}).

-record(nclock, {
  key :: node(), 
  lclock :: non_neg_integer()  %% logical clock
}).
