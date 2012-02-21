%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @doc
%%% EJMS supervisor
%%% @end
%%%-------------------------------------------------------------------
-module(ejms_sup).
-author(d87).
-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

-spec init(Args :: any()) -> {ok, { SupFlags :: any(), ChildSpec :: list() }} | ignore | {error, any()}.
init([]) ->
    RestartStrategy = one_for_all,
    MaxRestarts = 1,
    MaxSecondsBetweenRestarts = 2000,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    EJMS = {'ejms_srv', {'ejms_srv', start_link, []},
          permanent, 15000, worker, ['ejms_srv']},

    {ok, {SupFlags, [EJMS]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
    
