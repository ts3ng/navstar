{application,erlzk,
             [{description,"A Pure Erlang ZooKeeper Client (no C dependency)"},
              {vsn,"0.6.2"},
              {registered,[erlzk_sup,erlzk_conn_sup]},
              {applications,[kernel,stdlib,crypto]},
              {mod,{erlzk_app,[]}},
              {modules,[erlzk,erlzk_app,erlzk_codec,erlzk_conn,erlzk_conn_sup,
                        erlzk_heartbeat,erlzk_sup]}]}.
