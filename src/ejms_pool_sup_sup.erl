%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @doc
%%% Spawning pool top supervisor, and API module
%%% @end
%%%-------------------------------------------------------------------
-module(ejms_pool_sup_sup).
-author(d87).
-behaviour(supervisor).

%% API
-export([start_link/3]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%% MFA of worker's start_link function.
start_link(Module, Function, Args) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, [Module, Function, Args]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

% -spec init(Args :: any()) -> {ok, { SupFlags :: any(), ChildSpec :: list() }} | ignore | {error, any()}.
init(MFA) ->
    RestartStrategy = one_for_all,
    MaxRestarts = 60,
    MaxSecondsBetweenRestarts = 100,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    WorkerSupervisor = {'ejms_pool_sup', {'ejms_pool_sup', start_link, MFA},
          permanent, 2000, supervisor, ['ejms_pool_sup']},

    PoolServer = {'ejms_pool_srv', {'ejms_pool_srv', start_link, []},
          permanent, 2000, worker, ['ejms_pool']},

    {ok, {SupFlags, [WorkerSupervisor, PoolServer]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
    
