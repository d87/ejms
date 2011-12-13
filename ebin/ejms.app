{application, ejms,
 [{description, "Erlang Jabber Mail Service" },
  {vsn, "0.5" },
  {modules, [ejms_app, ejms_sup, ejms, ejms_worker, ejms_db,
  			ejms_pool_srv, ejms_pool_sup, ejms_pool_sup_sup, ejms_pool, pop3]},
  {registered,[ejms, ejms_db, ejsm_pool_srv, ejms_pool_sup]},
  {applications, [crypto,public_key,ssl,kernel,stdlib]},
  {mod, {ejms_app,[]}}
 ]}.
