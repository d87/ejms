%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @doc
%%% Spawning pool top supervisor, and API module
%%% @end
%%%-------------------------------------------------------------------
-module(ejms_pool).
-author(d87).

%% API
-export([start_link/3]).
-export([enqueue/1, push/1, is_empty_queue/0, wait_for_queue/0, wait_for_queue/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(Module, Function, Args) ->
    ejms_pool_sup_sup:start_link(Module, Function, Args).

-spec push(Task :: binary()) -> ok.
push(Task) ->
    ejms_pool_srv:push(Task).

-spec enqueue(Task :: binary()) -> started | enqueued.
enqueue(Task) ->
    ejms_pool_srv:enqueue(Task).

-spec is_empty_queue() -> boolean().
is_empty_queue() ->
    ejms_pool_srv:is_empty_queue().

-spec wait_for_queue() -> ok.
wait_for_queue() ->
    ejms_pool_srv:wait_for_queue(infinity).

-spec wait_for_queue(integer() | infinity) -> ok.
wait_for_queue(Timeout) ->
    ejms_pool_srv:wait_for_queue(Timeout).
