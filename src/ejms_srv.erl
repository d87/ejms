%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @copyright (C) 2011, 
%%% @doc
%%%
%%% @end
%%% Created : 25 Oct 2011 by  <>
%%%-------------------------------------------------------------------
-module(ejms_srv).
-author(d87).
-behaviour(gen_server).

-include_lib("exmpp/include/exmpp_client.hrl").
-include_lib("exmpp/include/exmpp_xml.hrl").
-include_lib("exmpp/include/exmpp_jid.hrl").
-include_lib("exmpp/include/exmpp_nss.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).
-compile(export_all).
-export([process_packet/2, handle_iq/4]).

-import(exmpp_component, [send_packet/2]).

-define(SERVER, ?MODULE).


-define(COMPONENT, "component.d87.cc").
-define(COMPONENT_NICK, "Supa service").
-define(SERVER_HOST, "localhost").
-define(SERVER_PORT, 8888).
-define(SECRET, "mizuage").

-define(CRYPTO_KEY, [194, 209, 223, 179, 53, 206, 76, 251, 127, 115, 107, 169, 95, 170, 174, 91, 96, 129, 239, 143, 71, 93, 201, 227, 151, 162, 186, 145, 12, 241, 17, 215, 9, 107, 143, 195, 136, 108, 40, 177, 12, 105, 4, 164, 174, 29, 119, 251, 23, 230, 84, 17, 226, 154, 4, 9, 26, 21, 171, 239, 4, 198, 155, 29, 130, 18, 252, 73, 51, 180, 139, 119, 118, 208, 19, 211, 186, 137, 81, 233, 48, 234, 248, 167, 37, 88, 191, 167, 28, 185, 46, 77, 131, 94, 145, 155, 102, 2, 20, 114, 58, 41, 81, 165, 181, 231, 6, 137, 161, 58, 216, 81, 31, 190, 60, 86, 129, 232, 38, 139, 223, 146, 173, 100, 17, 5, 46, 9, 186, 159, 71, 140, 179, 97, 28, 217, 1, 99, 47, 251, 114, 197, 19, 84, 77, 210, 163, 201, 180, 82, 82, 162, 117, 127, 233, 26, 2, 166, 238, 212, 47, 133, 236, 186, 88, 30, 235, 11, 90, 240, 50, 28, 108, 190, 61, 61, 19, 222, 9, 96, 127, 250, 76, 15, 153, 93, 155, 54, 179, 167, 91, 207, 37, 123, 191, 169, 242, 20, 18, 134, 23, 55, 60, 238, 73, 114, 219, 225, 246, 87, 69, 35, 219, 13, 125, 247, 93, 73, 45, 168, 140, 81, 184, 123, 216, 25, 252, 90, 148, 32, 133, 22, 2, 252, 177, 155, 116, 152, 53, 104, 230, 14, 10, 105, 252, 54, 68, 183, 43, 53, 41, 218, 73, 149, 234, 7]).
-define(CRYPTO_IVEC, [165, 88, 46, 146, 120, 144, 164, 131, 108, 125, 220, 104, 221, 73, 41, 200, 94, 110, 171, 7, 202, 82, 220, 99, 161, 162, 153, 17, 107, 231, 110, 35, 31, 100, 1, 177, 54, 188, 228, 58, 211, 63, 34, 15, 54, 4, 133, 150, 51, 32, 117, 68, 101, 43, 12, 194, 128, 226, 210, 183, 207, 66, 191, 253, 220, 30, 226, 17, 202, 189, 139, 1, 134, 120, 248, 12, 5, 44, 200, 122, 117, 32, 47, 237, 14, 205, 72, 191, 40, 187, 150, 156, 237, 153, 134, 216, 196, 95, 253, 181, 249, 113, 121, 190, 19, 237, 77, 247, 209, 180, 141, 18, 12, 212, 190, 200, 229, 186, 199, 183, 166, 219, 23, 69, 43, 141, 138, 145]
).

-include("../include/ejms.hrl").

-record(state, {
    session,
    users
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local,?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:call(?MODULE, stop).


-spec user_available(BareJID :: binary()) -> ok.
user_available(BareJID) ->
    gen_server:call(?MODULE, {user_available, BareJID}).

-spec user_unavailable(BareJID :: binary()) -> ok.
user_unavailable(BareJID) ->
    gen_server:call(?MODULE, {user_unavailable, BareJID}).

-spec users() -> any().
users() ->
    gen_server:call(?MODULE, getusers).

% -spec add_resource(JID :: #jid{}, Priority :: integer()) -> ok.
% add_resource(JID, Priority) ->
    % gen_server:call(?MODULE, {add_resource, JID, Priority}).

-spec notify(BareJID :: binary(), MBID :: binary()) -> ok.
notify(BareJID, MBID) ->
    gen_server:call(?MODULE, {notify, BareJID, MBID}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([]) -> {ok, #state{}}.
init([])->
    Session = exmpp_component:start_link(),
    exmpp_component:auth(Session, ?COMPONENT, ?SECRET),
    _StreamID = exmpp_component:connect(Session, ?SERVER_HOST, ?SERVER_PORT),
    ok = exmpp_component:handshake(Session),

    ejms_pool:start_link(ejms_worker, retrieve, []),
    spawn_link(fun() -> timer_loop( 3600000 ) end),
    % spawn_link(fun() ->
        % mailport:start_link(),
        % mailnotify_loop()
    % end),

    %% broadcast available presence to all subscribed users
    spawn(fun() -> broadcast_presence(Session) end),
    process_flag(trap_exit, true),

    {ok, #state{ session = Session, users = gb_sets:new() }}.

-spec handle_call(any(), any(), #state{}) -> {reply, any(), #state{}} | {noreply, #state{}}.
handle_call({user_available, BareJID}, _From, #state{ users = Users} = State) ->
    Users2 = gb_sets:add_element(BareJID, Users),
    {ok, A} = ejms_db:user(BareJID),
    lists:foreach(fun(Pair) -> ejms_pool:push({BareJID, Pair}) end, A#ejms_account.mailboxes),
    % ejms_pool:push(BareJID),
    {reply, ok, State#state{ users = Users2 }};
handle_call({user_unavailable, BareJID}, _From, #state{ users = Users} = State) ->
    Users2 = gb_sets:del_element(BareJID, Users),
    {reply, ok, State#state{ users = Users2 }};
handle_call(getusers, _From, #state{ users = Users} = State) ->
    {reply, Users, State};
% handle_call({add_resource, JID, Priority}, _From, #state{ workers = Workers } = State) ->
    % BareJID = exmpp_jid:prep_bare_to_binary(JID),
    % Workers2 = case dict:find(BareJID, Workers) of
        % {ok, #contact{ resources = Res0 } = Contact} ->
            % dict:store(BareJID, Contact#contact{ resources = sets:add_element({JID, Priority}, Res0) }, Workers);
        % error ->
            % {ok, UserConf} = ejms_db:user(BareJID),
            % WorkerPid = spawn_link(fun() -> worker_process (UserConf) end),
            % dict:store(BareJID, #contact{ pid = WorkerPid }, Workers)
    % end,
    % {reply, ok, State#state{ workers = Workers2 }};

handle_call({notify, BareJID, MBID}, _From, #state{ session = Session } = State) ->
    IOList = io_lib:format("New mail on ~s", [MBID]),
    Body = list_to_binary(IOList),

    %%% Here I learned that less than zero priority for resources was very bad idea.
    % TopResource = case dict:find(BareJID, Workers) of
    %     {ok, #contact{ resources = Res }} ->
    %         {TR, _} = sets:fold(fun(Elem, void) ->
    %                                             Elem;
    %                                         ({_,P} = New, {_,MaxP} = Skip) ->
    %                                             if
    %                                                 P >= MaxP -> New;
    %                                                 true -> Skip
    %                                             end
    %                                         end, void, Res),
    %         TR;
    %     error -> BareJID    
    % end,

    Response =  exmpp_stanza:set_sender(
                    exmpp_stanza:set_recipient(
                        exmpp_message:chat(Body),
                        BareJID),
                    ?COMPONENT),
    

    send_packet(Session, Response),
    {reply, ok, State};

%%% DEBUG
handle_call(state, _From, State) ->
    {reply, State, State};

handle_call(stop, _From, State) ->
    {stop, normal, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

-spec handle_cast(any(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(any(), #state{}) -> {noreply, #state{}}.
%% all packets from server are dispatched here
handle_info(#received_packet{} = Packet, #state{session = S} = State) ->
    spawn(fun() -> process_packet(S, Packet) end),
    {noreply, State};

handle_info({'EXIT', _Pid, _Reason}, State) ->
    % trap exit
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(any(), #state{}) -> any().
terminate(_Reason, #state{ session = Session } = _State) ->
    broadcast_presence_unavailable(Session),
    exmpp_component:stop(Session),
    ok.

-spec code_change(any(), any(), any()) -> {ok, any()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Stanza handlers
%%%===================================================================


process_packet(Session, #received_packet{packet_type = 'iq', type_attr=Type, raw_packet = IQ})->
    handle_iq(Session, Type, exmpp_xml:get_ns_as_atom(exmpp_iq:get_payload(IQ)), IQ);

process_packet(Session, #received_packet{packet_type = 'presence', type_attr=Type, raw_packet = Presence})->
    handle_presence(Session, Type, Presence);

process_packet(Session, #received_packet{packet_type = 'message', raw_packet = Message}) ->
    handle_message(Session, Message).

timer_loop( Time ) ->
    receive
    after
        Time -> ok
    end,
    ejms_pool:wait_for_queue(),
    Users = users(),
    gb_sets:fold(fun(JID, _Acc) ->
                    {ok, A} = ejms_db:user(JID),
                    lists:foreach(fun(Pair) -> ejms_pool:enqueue({JID, Pair}) end, A#ejms_account.mailboxes)
                 end, void, Users),
    timer_loop(Time).

broadcast_presence(Session) ->
    Subs = ejms_db:subscribers_list(),
    lists:foldl(fun ({ JID, to }, _Acc) ->  send_packet(Session, presence_probe(JID));

                    ({ JID, from}, _Acc) -> send_packet(Session, presence_available(JID));

                    ({ JID, both}, _Acc) -> send_packet(Session, presence_probe(JID)),
                                            send_packet(Session, presence_available(JID))
                end, [], Subs).

broadcast_presence_unavailable(Session) ->
    Subs = ejms_db:subscribers_list(),
    lists:foldl(fun ({ JID, from}, _Acc) -> send_packet(Session, presence_unavailable(JID));
                    ({ JID, both}, _Acc) -> send_packet(Session, presence_unavailable(JID))
                    %% ({ JID, to}, _Acc) -> send_packet(Session, presence_unavailable(JID))
                end, [], Subs).

%%=================================================
%% Message
%%=================================================
make_mailbox(MBID, U, P, Host, Port, SSL) when byte_size(MBID) < 30, byte_size(U) < 50, byte_size(P) < 30,
                                               byte_size(Host) < 100, byte_size(Port) < 6, byte_size(SSL) < 6 ->
    SSLStatus = case SSL of
        <<"SSL">> -> true;
        <<"NOSSL">> -> false;
        _ -> error
    end,
    case SSLStatus of
        error -> error;
        _ ->
            {MBID, #ejms_mailbox{ username = U, password = P, host = Host,
                    port = list_to_integer(binary_to_list(Port)), ssl = SSLStatus }}
    end;
make_mailbox(_MBID, _U, _P, _Host, _Port, _SSL) -> error.


-spec command(JID :: binary(), Bin :: binary()) -> binary().
command(BareJID, Bin) ->
    case    gb_sets:is_element(BareJID, users()) of
    true->
        R = command1(BareJID, Bin),
        if 
            is_list(R) -> list_to_binary(R);
            true -> R
        end;
    false ->
        %% It's better to allow text registration as well actually
        <<"Not authorized">>
    end.

command1(BareJID, <<"maillist",_Rest/binary>>) ->
    {ok, A} = ejms_db:user(BareJID),
    io:format("~p~n",[A]),
    lists:reverse(
        lists:foldl(
            fun({MBID, #ejms_mailbox{ username = U, password = P, host = Host, port = Port, ssl = SSLFlag}}, Acc) ->
                SSLStatus = case SSLFlag of true -> "yes"; false -> "no" end,
                io:format("2"),
                [io_lib:format("=== ~s ===\nUsername: ~s\nPassword: ~s\nHost: ~s\nPort: ~B\nSSL: ~s\n",[MBID, U, P, Host, Port, SSLStatus])|Acc]
            end,
            ["Registered mailboxes:\n"], A#ejms_account.mailboxes));
command1(BareJID, <<"mailadd",Rest/binary>>) ->
    case Rest of
        <<>> -> <<"Format: mailadd <mailbox name> <username> <password> <host> <port> [SSL/NOSSL]">>;
        _Any ->
            R = case re:split(Rest, " +", [{return, binary}]) of
                [<<>>, MBID, U, P, Host, Port, SSL] ->
                    make_mailbox(MBID, U, P, Host, Port, SSL);
                _Other -> error
            end,
            case R of
                {Name, Mailbox} ->
                    case ejms_worker:validate(Mailbox) of
                        ok ->
                            ok = ejms_db:update_mailbox(BareJID, Name, Mailbox),
                            <<"New mailbox registered.">>;
                        {error, badconn} ->
                            io_lib:format("Error: Couldn't connect to ~s:~B",
                                        [Mailbox#ejms_mailbox.host, Mailbox#ejms_mailbox.port]);
                        {error, badauth} ->
                            <<"Error: Couldn't authenticate.">>
                    end;
                error ->
                    <<"Error: Incorrect/incomplete data.">>
            end
    end;

command1(BareJID, <<"maildel",Rest/binary>>) ->
    case Rest of
        <<>> -> <<"Format: maildel <mailbox name>">>;
        _Any ->
            case re:split(Rest, " +", [{return, binary}]) of
                [<<>>, MBID] ->
                    case ejms_db:delete_mailbox(BareJID, MBID) of
                        ok -> io_lib:format("~s succesfully removed.",[MBID]);
                        mailbox_not_found -> io_lib:format("~s does not exist.",[MBID])
                    end;
                _Other ->
                    <<"Error: mailbox name missing.">>
            end
    end;

command1(_BareJID, Any) ->
    Any.

handle_message(Session, Message) ->
    From = exmpp_jid:parse(exmpp_stanza:get_sender(Message)),
    BareJID = getbarebin(Message),
    ResponseBody = command(BareJID, exmpp_message:get_body(Message)),
    % Response =  exmpp_xml:element(?NS_COMPONENT_ACCEPT, 'message',
                    % [?XMLATTR(<<"type">>, <<"chat">>),
                     % ?XMLATTR(<<"from">>, ?COMPONENT),
                     % ?XMLATTR(<<"to">>, exmpp_jid:to_binary(From))],
                        % [?XMLEL4(?NS_COMPONENT_ACCEPT, 'body', [], [?XMLCDATA(Body)])]),
    Response =  exmpp_stanza:set_sender(
                    exmpp_stanza:set_recipient(
                        exmpp_message:chat(ResponseBody),
                        exmpp_jid:to_binary(From)),
                    ?COMPONENT),
    % Response = exmpp_message:set_body(
        % exmpp_stanza:reply_without_content(Message),
        % Body),
                            
    send_packet(Session, Response).

%%=================================================
%% Info/query
%%=================================================

handle_iq(Session, "get", ?NS_DISCO_INFO, IQ) ->
    Identity = exmpp_xml:element(?NS_DISCO_INFO, 'identity', [
                                    exmpp_xml:attribute(<<"category">>, <<"component">>),
                                    exmpp_xml:attribute(<<"type">>, <<"presence">>),
                                    exmpp_xml:attribute(<<"name">>, <<?COMPONENT_NICK>>)
                                    ],
								 []),
    IQRegisterFeature = exmpp_xml:element(?NS_DISCO_INFO, 'feature', [exmpp_xml:attribute(<<"var">>, ?NS_INBAND_REGISTER_s)],[]),
    Result = exmpp_iq:result(IQ, exmpp_xml:element(?NS_DISCO_INFO, 'query', [], [Identity, IQRegisterFeature])),
    send_packet(Session, Result);

handle_iq(Session, "get", ?NS_INBAND_REGISTER, IQ) ->
    % From = exmpp_jid:parse(exmpp_stanza:get_sender(IQ)),
    % BareJID = exmp_jid:prep_bare_to_binary(From),
    %% exmpp_stanza:get_sender extracts binary with full jid string, exmpp_jid:parse converts it into jid record
    BareJID = getbarebin(IQ),
    {Name, Mailbox} = case ejms_db:user(BareJID) of
        {ok, A} ->
            case A#ejms_account.mailboxes of
                [H|_T] -> H;
                [] -> {<<"Mailbox1">>, #ejms_mailbox{}}
            end; 
        not_found -> {<<"Mailbox1">>, #ejms_mailbox{}}
    end,
    Form = make_form(<<"Fill in your mail account credentials">>, Name, Mailbox),
    FormInstructions = exmpp_xml:element(?NS_INBAND_REGISTER, 'instructions', [],
                        [?XMLCDATA(<<"FormInstructions">>)]),
 
    Result = exmpp_iq:result(IQ, exmpp_xml:element(?NS_INBAND_REGISTER, 'query', [], 
        [FormInstructions, Form])),
    send_packet(Session, Result);

handle_iq(Session, "set", ?NS_INBAND_REGISTER, IQ) ->
    From = exmpp_jid:parse(exmpp_stanza:get_sender(IQ)),
    BareJID = exmpp_jid:prep_bare_to_binary(From),
    Form = exmpp_xml:get_element(exmpp_iq:get_payload(IQ), ?NS_DATA_FORMS, 'x'),
    {Name, Mailbox} = parse_form(Form),
    %% will create account if it's not already present
    ok = ejms_db:update_mailbox(BareJID, Name, Mailbox),

    Result = exmpp_iq:result(IQ),

    %% Succesful registration
    send_packet(Session, Result),

    send_packet(Session, presence_subscribe(exmpp_jid:bare_to_binary(From)));

    % ErrorCond = exmpp_xml:element(undefined, 'error', 
                        % [exmpp_xml:attribute(<<"code">>, <<"409">>),
                         % exmpp_xml:attribute(<<"type">>, <<"cancel">>)],
                        % [exmpp_xml:element(?NS_STANZA_ERRORS, 'conflict')]),

    %% Requires to     
    % ErrorCond2 = exmpp_xml:element(undefined, 'error', 
                        % [exmpp_xml:attribute(<<"code">>, <<"406">>),
                         % exmpp_xml:attribute(<<"type">>, <<"modify">>)],
                        % [exmpp_xml:element(?NS_STANZA_ERRORS, 'non-acceptable')]),

    % Err = exmpp_iq:error(IQ, ErrorCond2),
    % send_packet(Session, Err);


    % exmpp_iq:get_payload - Extract the request, the result or the error from IQ


    % From = exmpp_jid:parse(exmpp_stanza:get_sender(IQ)),

handle_iq(_Session, Type, Namespace, IQ) ->
    io:format("Type:~p~nNamespace:~p~n~p~n", [Type, Namespace, IQ]),
    ok.
		  

%%=================================================
%% PRESENCE
%%=================================================


%% user sends confirmation that we're subscribed to his presence
handle_presence(_Session, "subscribed", Presence) ->
    From = getbarebin(Presence),
    io:format("~p subscribed~n",[From]),
    case ejms_db:user(From) of
        {ok, #ejms_account{ subscription_state = State } = User} ->
            State1 = transition(State, subscribed),
            io:format("~p -> ~p~n",[State, State1]),
            ejms_db:write_user(User#ejms_account{ subscription_state = State1 });
        not_found -> unknown_user
    end;

%% user request to subscribe to our presence
handle_presence(Session, "subscribe", Presence) ->
    From = getbarebin(Presence),
    io:format("~p subscribe~n",[From]),
    Status = case ejms_db:user(From) of
            {ok, #ejms_account{subscription_state = State} = User} -> 
                State1 = transition(State, subscribe),
                io:format("~p -> ~p~n",[State, State1]),
                ejms_db:write_user(User#ejms_account{ subscription_state = State1 });
            not_found -> 
                unknown_user
    end,
    case Status of
        ok ->
            send_packet(Session, presence_subscribed(From)),
            send_packet(Session, presence_available(From));
        unknown_user ->
            send_packet(Session, presence_unsubscribed(From))
    end;

handle_presence(Session, "unsubscribe", Presence) ->
    From = getbarebin(Presence),
    io:format("~p unsubscribe~n",[From]),
    ejms_db:delete_user(From),
    send_packet(Session, presence_unsubscribed(From));

handle_presence(_Session, "unsubscribed", Presence) ->
    From = getbarebin(Presence),
    io:format("~p unsubscribed~n",[From]),
    ejms_db:delete_user(From);

handle_presence(_Session, "unavailable", Presence) ->
    From = getbarebin(Presence),
    io:format("~p unavailable~n",[From]),
    user_unavailable(From);

handle_presence(_Session, "available", Presence) ->
    From = getbarebin(Presence),
    io:format("~p available~n",[From]),
    user_available(From);
    % JID = exmpp_jid:parse(exmpp_stanza:get_sender(Presence)),
    % Childs = exmpp_xml:get_child_elements(Presence),
    % PriorityBin = lists:foldl(fun (#xmlel{ name = priority } = El, Acc) ->
                        % exmpp_xml:get_cdata(El);
                    % (_, Acc) -> Acc
                % end, <<"0">>, Childs),
    %%% extracting resource priority from presence stanza, with 0 as default
    % Priority = list_to_integer(binary_to_list(PriorityBin)),

    % io:format("~p available~n~s~n",[exmpp_jid:to_binary(JID),exmpp_xml:document_to_iolist(Presence)]),
    % add_resource(JID, Priority); %% if it's not already there

handle_presence(Session, "probe", Presence) ->
    From = getbarebin(Presence),
    io:format("~p probe~n",[From]),
    send_packet(Session, presence_available(From));

handle_presence(_Session, Type, Presence) ->
    io:format("~p~n~p~n",[Type,Presence]).

%%% ------------ Transition table  state x action -> new state 
%% Note: this doesn't handle all case, nor keep trac of wich subscription request we have sent,
%% but for our example this is enough. For a complete description of subscription states and 
%% transitions, see http://xmpp.org/rfcs/rfc3921.html
-spec transition(State :: none | to | from | both,  Action :: subscribe | subscribed) -> from | both | to.
transition(none, subscribe) -> 'from';
transition(to, subscribe) -> 'both';
transition(from, subscribe) -> 'from';
transition(both, subscribe) -> 'both';
transition(none, subscribed) -> 'to';
transition(to, subscribed) -> 'to';
transition(from, subscribed) -> 'both';
transition(both, subscribed) -> 'both'.

-spec presence() -> #xmlel{}.
presence() ->
    exmpp_xml:element(?NS_COMPONENT_ACCEPT, 'presence', [?XMLATTR(<<"from">>, ?COMPONENT)], []).

-spec presence(Type :: binary()) -> #xmlel{}.
presence(Type) ->
    exmpp_xml:element(?NS_COMPONENT_ACCEPT, 'presence',
                            [?XMLATTR(<<"type">>, Type),
                             ?XMLATTR(<<"from">>, ?COMPONENT)],
                             []).

-spec presence(JID :: binary() | tuple(), Type :: binary()) -> #xmlel{}.
presence(JID, Type) ->
    exmpp_stanza:set_recipient( presence(Type), JID).

presence_subscribe(JID) ->
    Presence = presence(JID, <<"subscribe">>),
    exmpp_xml:append_child(Presence,
                exmpp_xml:element(?NS_USER_NICKNAME, 'nick', [], [?XMLCDATA(<<?COMPONENT_NICK>>)] )).

%% presence withou type
presence_available(JID) ->
    exmpp_stanza:set_recipient( presence(), JID).

presence_unavailable(JID) ->
    presence(JID, <<"unavailable">>).
presence_subscribed(JID) ->
    presence(JID, <<"subscribed">>).
presence_unsubscribed(JID) ->
    presence(JID, <<"unsubscribed">>).
presence_probe(JID) ->
    presence(JID, <<"probe">>).


%%%===================================================================
%%% Internal functions
%%%===================================================================


getbarebin(Packet) ->
    From = exmpp_jid:parse(exmpp_stanza:get_sender(Packet)),
    exmpp_jid:prep_bare_to_binary(From).

create_field(Type, Var, Label) ->
    create_field(Type, Var, Label, []).
create_field(Type, Var, Label, Opts) ->
    Children = lists:foldl(fun ({value, Value},Acc)->
                                    [exmpp_xml:element(?NS_DATA_FORMS, 'value', [], [?XMLCDATA(Value)]) | Acc];
                               (required, Acc) ->
                                    [exmpp_xml:element(?NS_DATA_FORMS, 'required', [], []) | Acc]
                                end, [], Opts),
    % parse_field_opts(Opts,[]),
    Attrs = case Label of
        void -> [?XMLATTR(<<"type">>, Type), ?XMLATTR(<<"var">>, Var)];
        _ -> [?XMLATTR(<<"type">>, Type), ?XMLATTR(<<"var">>, Var), ?XMLATTR(<<"label">>, Label)]
    end,
    exmpp_xml:element(?NS_DATA_FORMS, 'field', Attrs, Children ).


boolean_to_form(true) -> <<"1">>;
boolean_to_form(false) -> <<"0">>.

form_to_boolean(<<"1">>) -> true;
form_to_boolean(<<"0">>) -> false.

% -spec make_form(#user_conf{}, Instructions :: binary()) -> #xmlel{}.
% make_form(#user_conf{} = UserConf, Instructions) ->
gen_form_opts(Value) ->
    case Value of
        undefined -> [];
        Val -> [{value,Val}]
    end.
gen_form_opts(Value, required) ->
    [ required | gen_form_opts(Value)];
gen_form_opts(Value, _) -> gen_form_opts(Value).

make_form(Instructions, MBID, #ejms_mailbox{ username = Username, password = Password, host = Host, port = Port, ssl = SSL } = _Mailbox) ->

    InstructionElement = exmpp_xml:element(?NS_DATA_FORMS, 'instructions', [], [?XMLCDATA(Instructions)]),  

    FormTypeField = create_field(<<"hidden">>, <<"FORM_TYPE">>, void, [{value, <<"jabber:iq:register">> }]),
    MailboxNameField = create_field(<<"text-single">>, <<"mailbox-id">>, <<"Mailbox Name">>, gen_form_opts(MBID, required)),
    UsernameField = create_field(<<"text-single">>, <<"username">>, <<"Username">>, gen_form_opts(Username, required)),
    PasswordField = create_field(<<"text-private">>, <<"password">>, <<"Password">>, gen_form_opts(Password, required)),
    ServerField = create_field(<<"text-single">>, <<"host">>, <<"POP3 Server">>, gen_form_opts(Host, required)),
    ServerPortField = create_field(<<"text-single">>, <<"port">>, <<"Port">>, gen_form_opts(Port, required)),
    SSLField = create_field(<<"boolean">>, <<"ssl_checkbox">>, <<"SSL">>, gen_form_opts(boolean_to_form(SSL), required)),
    % ServerPortField = create_field(<<"text-single">>, <<"mailserver">>, <<"Mail server">>, [required]),

    exmpp_xml:element(?NS_DATA_FORMS, 'x', [?XMLATTR(<<"type">>,<<"form">>)], 
                    [InstructionElement, FormTypeField, MailboxNameField, UsernameField, PasswordField, ServerField, ServerPortField, SSLField ]).



-spec parse_form(#xmlel{}) -> tuple().
parse_form(Form) ->
    Fields = exmpp_xml:get_elements(Form,  ?NS_DATA_FORMS, 'field'),
    Pairs = lists:map(fun(Field) ->
                    {exmpp_xml:get_attribute_as_binary(Field, <<"var">>, <<>>),
                    exmpp_xml:get_cdata(exmpp_xml:get_element(Field, 'value'))}
                end, Fields),
    lists:foldl(fun ({<<"mailbox-id">>, Value}, {_MBID, Mailbox}) ->
                        {Value, Mailbox};

                    ({<<"username">>, Value}, {MBID, Mailbox}) ->
                        {MBID, Mailbox#ejms_mailbox{username = Value}};

                    ({<<"password">>, Value}, {MBID, Mailbox}) ->
                        {MBID, Mailbox#ejms_mailbox{password = Value}};

                    ({<<"host">>, Value}, {MBID, Mailbox}) ->
                        {MBID, Mailbox#ejms_mailbox{host = Value}};

                    ({<<"port">>, Value}, {MBID, Mailbox}) ->
                        V1 = list_to_integer(binary_to_list(Value)),
                        {MBID, Mailbox#ejms_mailbox{port = V1}};

                    ({<<"ssl_checkbox">>, Value}, {MBID, Mailbox}) ->
                        {MBID, Mailbox#ejms_mailbox{ssl = form_to_boolean(Value)}};

                    % ({<<"FORM_TYPE">>, <<"jabber:iq:register">>}, Mailbox) ->
                        % Mailbox;

                    ({_, _Value}, {MBID, Mailbox}) ->
                        {MBID, Mailbox}
                end, {<<>>, #ejms_mailbox{}}, Pairs).
