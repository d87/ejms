-module(ejms_worker).
-author(d87).
-export([validate/1, retrieve/1, getlasthash/1]).

-include("../include/ejms.hrl").

% retrieve() ->
    % void.
retrieve(UID) ->
    Pid = spawn_link(fun() -> retrieve1( UID) end),
    {ok, Pid}.

retrieve1( UID ) ->
    {ok, Account } = ejms_db:user(UID),
    #ejms_account{ mailbox = Mailbox } = Account,
    {ok, NewHash} = getlasthash(Mailbox),
    io:format("succesful check~n"),
    if
        NewHash =/= Mailbox#ejms_mailbox.lasthash ->
            NewMailbox = Mailbox#ejms_mailbox{ lasthash = NewHash },
            NewAccount = Account#ejms_account{ mailbox = NewMailbox },
            ejms_db:write_user(NewAccount),
            ejms:notify(UID),
            newmail;
        true -> ok
    end.


getlasthash(#ejms_mailbox{ username = Username1, password = Password1, host = Host1, port = Port, ssl = SSL } = _Mailbox) ->
    Username = binary_to_list(Username1),
    Password = binary_to_list(Password1),
    Host = binary_to_list(Host1),
    Opts = case SSL of
        true -> [ssl];
        false -> []
    end,
    {ok, Conn} = pop3:connect(Host, Port, Opts),
    {ok, _AuthResponse} = pop3:auth(Conn, Username, Password),
    {ok, Num, _MaildropSize} = pop3:stat(Conn),
    {ok, _Resp, Bin} = pop3:retr(Conn,Num),
    pop3:quit(Conn),
    {ok, crypto:sha(Bin)}.


validate(#ejms_mailbox{ username = Username1, password = Password1, host = Host1, port = Port, ssl = SSL } = _Mailbox) ->
    Username = binary_to_list(Username1),
    Password = binary_to_list(Password1),
    Host = binary_to_list(Host1),
    Opts = case SSL of
        true -> [ssl];
        false -> []
    end,
    case pop3:connect(Host, Port, Opts) of
        {ok, Conn} ->
            case pop3:auth(Conn, Username, Password) of
                {ok, _AuthResponse} ->  
                    pop3:quit(Conn),
                    ok;
                _ ->
                    {error, badauth}
            end;
        _ ->
            {error, badconn}
    end.
