-ifndef(EJMS_HRL).
-define(EJMS_HRL, true).


-record(ejms_mailbox, {
	username,
    password,
    host,
    port = 143, %% default port, 993 over ssl
    ssl = false :: boolean(),
    lasthash = <<>> :: binary()
}).

-record(ejms_account, {
    jid :: binary(),
    mailbox = #ejms_mailbox{} :: #ejms_mailbox{},
    active = true :: boolean(),
    subscription_state = none :: none | to | from | both
}).


-endif.
