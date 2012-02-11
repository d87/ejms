-module(ejms_db).
-author(d87).

-include_lib("stdlib/include/qlc.hrl").

-include("../include/ejms.hrl").

-export([start/0, user/1, write_user/1, delete_user/1, subscribers_list/0, update_mailbox/3, delete_mailbox/2]).

-spec start() -> ok.
start() ->
    Node = node(),
    case mnesia:create_schema([Node]) of
        ok -> 
            mnesia:start(),
            {atomic, ok} = mnesia:create_table(ejms_account, [
                    {disc_copies, [Node]},
                    {attributes, record_info(fields, ejms_account)}
                ]);

        {error, {Node, {already_exists,_}}} -> 
            mnesia:start()
    end,
    ok.

% -spec wait_for_tables() -> ok.
% wait_for_tables() ->
    % mnesia:wait_for_tables([ejms_account],20000).

-spec user(BareJID :: binary()) -> {ok, #ejms_account{}} | not_found .
user(BareJID) ->
    case mnesia:dirty_read(ejms_account, BareJID) of
        [A] -> {ok, A};
        [] -> not_found
    end.

-spec write_user(A :: #ejms_account{}) -> ok .
write_user(A) -> 
    Fun = fun() -> mnesia:write(A) end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

%%% @doc
%%% Used to update mailboxes and also to register new accounts.
%%% @end
-spec update_mailbox(BareJID :: binary(), MBID :: binary(), NewMailbox :: #ejms_mailbox{}) -> ok .
update_mailbox(BareJID, MBID, NewMailbox) -> 
    Fun = fun() ->
        A = case mnesia:read(ejms_account, BareJID) of
                [Account] -> Account;
                [] -> #ejms_account{ jid = BareJID, mailboxes = []}
        end,
        B = A#ejms_account{ mailboxes = lists:keystore(MBID, 1, A#ejms_account.mailboxes, {MBID, NewMailbox}) },
        mnesia:write(B)
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

-spec delete_mailbox(BareJID :: binary(), MBID :: binary()) -> ok | mailbox_not_found.
delete_mailbox(BareJID, MBID) -> 
    Fun = fun() ->
        [A = #ejms_account{ mailboxes = Mailboxes}] = mnesia:read(ejms_account, BareJID),
        case lists:keymember(MBID, 1, Mailboxes) of
            true -> mnesia:write(A#ejms_account{ mailboxes = lists:keydelete(MBID, 1, Mailboxes) });
            false -> mailbox_not_found
        end
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.    

-spec delete_user(BareJID :: binary()) -> ok.
delete_user(BareJID) -> 
    Fun = fun() -> mnesia:delete(ejms_account, BareJID, write) end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

do(Q) ->
    Fun = fun() -> qlc:e(Q) end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

-spec subscribers_list() -> list().
subscribers_list() ->
    do(qlc:q( [{X#ejms_account.jid, X#ejms_account.subscription_state} || X <- mnesia:table(ejms_account), X#ejms_account.subscription_state =/= none ] )).
    
