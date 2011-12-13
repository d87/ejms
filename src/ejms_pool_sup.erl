%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @doc
%%% Spawning pool worker simple_one_for_one supervisor.
%%% @end
%%%-------------------------------------------------------------------
-module(ejms_pool_sup).
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

start_link(Module, Function, Args) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, [Module, Function, Args]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

-spec init(Args :: any()) -> {ok, { SupFlags :: any(), ChildSpec ::list() }} | ignore | {error, any()}.
init([M,F,A]) ->
    RestartStrategy = simple_one_for_one,
    MaxRestarts = 60,
    MaxSecondsBetweenRestarts = 100,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    Restart = temporary,
    Shutdown = 2000,
    Type = worker,

    AChild = {ignored, {M, F, A},
	      Restart, Shutdown, Type, [M]},

    % Note that when the restart strategy is simple_one_for_one,
    % the list of child specifications must be a list with one child specification only. (The Id is ignored).
    % No child process is then started during the initialization phase,
    % but all children are assumed to be started dynamically using supervisor:start_child/2.
    {ok, {SupFlags, [AChild]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

    
