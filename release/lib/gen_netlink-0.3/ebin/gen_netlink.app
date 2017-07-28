{application,gen_netlink,
             [{description,"Netlink socket toolkit"},
              {vsn,"0.3"},
              {modules,[gen_netlink_client,gen_netlink_sup,netlink_codec]},
              {registered,[]},
              {applications,[kernel,stdlib,lager,procket]},
              {env,[]}]}.
