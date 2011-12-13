-module(pop3).
-export([connect/2, connect/3, connect/4,
        quit/1, quit/2,
        rset/1,
        auth/3,
        stat/1,
        retr/2]).

-record(session, {socket,socketmodule}).
        

connect(Host,Port)->
    connect(Host,Port,[]).
connect(Host,Port,Opts)->
    connect(Host,Port,Opts,3000).    
connect(Host,Port,Opts,Timeout)->
    Module = case lists:member(ssl,Opts) of
        true  -> ssl;
        false -> gen_tcp
    end,

    case Module:connect(Host,Port,[binary, inet, {packet,raw}, {active,false}],Timeout) of
        {ok, Socket} ->
            Session = #session{ socket=Socket, socketmodule=Module },
            { ok, _Bin } = getresponse(Session),
            { ok, Session };
        Error -> Error
    end.


%% Gmail server ignores rset and delete messages anyway
quit(Session)->
    quit(Session,false).
quit(#session{socket = Socket, socketmodule = Module} = Session, RemoveFromServer) ->
    case RemoveFromServer of
        false -> rset(Session);
        true  -> ok
    end,
    sendcmd(Module, Socket, ["QUIT"]),
    Resp = getresponse(Session),
    Module:close(Socket),
    Resp.

rset(#session{socket = Socket, socketmodule = Module} = Session) ->
    sendcmd(Module, Socket, ["RSET"]),
    getresponse(Session).

auth(#session{socket = Socket, socketmodule = Module} = Session, User, Password) ->
    sendcmd(Module,Socket,["USER",User]),
    case getresponse(Session) of
        {ok, _UserResponse}->
            sendcmd(Module,Socket,["PASS", Password]),
            getresponse(Session);
        Error ->
            Error
    end.

stat(#session{socket = Socket, socketmodule = Module} = Session) ->
    sendcmd(Module, Socket, ["STAT"]),
    case getresponse(Session) of
        {ok, Response} ->
            {match, [[NumStr], [SizeStr]]} = re:run(Response, "([0-9]+)", [ global, {capture,first,list} ]),
            Num = list_to_integer(NumStr),
            Size = list_to_integer(SizeStr),
            {ok, Num, Size};
        Error ->
            Error
    end.

retr(#session{socket = Socket, socketmodule = Module} = Session, Index) when Index > 0->
    sendcmd(Module, Socket, ["RETR",integer_to_list(Index)]),
    getresponse(Session,true);
retr(_Session, _Index) -> {error, badindex}.
          
%%====================
%% Internal functions
%%====================

sendcmd(Module,Socket,CmdArgs)->
    Module:send(Socket, [string:join(CmdArgs," "), "\r\n"]).
    


is_terminated(<<>>) -> more;
is_terminated(<<_AtLeast:40,_/binary>> = Bin)->
    case split_binary(Bin, byte_size(Bin)-5) of
        {Rest,<<"\r\n.\r\n">>} ->
            { ok, Rest };
        _ ->
            more
    end;
is_terminated(_Bin) when is_binary(_Bin) -> more.

recv_until_terminated(Module, Socket, Data) ->
    case is_terminated(Data) of
        { ok, _Data1 } ->
            {ok, Data};
        more ->
            {ok, NewData} = Module:recv(Socket, 0, 5000),
            % io:format("S: ~p~n",[NewData]),
            recv_until_terminated(Module, Socket, <<Data/binary, NewData/binary>>)
    end.
    

getresponse(Session)->
    getresponse(Session,false).
getresponse(#session{ socket = Socket, socketmodule = Module } = _Session, IsMultiline) ->
    {ok, Data} = Module:recv(Socket, 0, 5000),
    case Data of
        <<$+,$O,$K,_/binary>> ->
            case IsMultiline of
                true ->
                    [Data2, SoFar] = binary:split(Data,[<<"\r\n">>]),
                    {ok, Multiline} = recv_until_terminated(Module,Socket,SoFar),
                    {ok, Data2, Multiline};
                false ->
                    {ok, Data}
            end;
        <<$-,$E,$R,$R,_/binary>> ->
            {error, Data}
    end.
