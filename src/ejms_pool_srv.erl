%%%-------------------------------------------------------------------
%%% @author  <d87>
%%% @doc
%%% Spawning pool server module, manages process queue.
%%% @end
%%%-------------------------------------------------------------------
-module(ejms_pool_srv).
-author(d87).
-behaviour(gen_server).


%% API
-export([start_link/0, stop/0]).
-export([enqueue/1, push/1, is_empty_queue/0, wait_for_queue/0, wait_for_queue/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
    queue,
    slots,
    wsup,
    halted
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

-spec push(Task :: binary()) -> ok.
push(Task) ->
    gen_server:call(?MODULE, {push, Task}).

-spec enqueue(Task :: binary()) -> started | enqueued.
enqueue(Task) ->
    gen_server:call(?MODULE, {enqueue, Task}).

-spec is_empty_queue() -> boolean().
is_empty_queue() ->
    gen_server:call(?MODULE, is_empty_queue).

-spec wait_for_queue() -> ok.
wait_for_queue() ->
    gen_server:call(?MODULE, wait_for_queue, infinity).

-spec wait_for_queue(integer() | infinity) -> ok.
wait_for_queue(Timeout) ->
    gen_server:call(?MODULE, wait_for_queue, Timeout).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([]) -> {ok, #state{}}.
init([])->
    Q = queue:new(),
    Sup = ejms_pool_sup,
    {ok, #state{ queue = Q, slots = 3, wsup = Sup, halted = [] }}.

-spec handle_call(any(), any(), #state{}) -> {reply, any(), #state{}} | {noreply, #state{}}.
handle_call({enqueue, Task}, _From, State = #state{ slots = N }) when N > 0 ->
    run_worker(Task),
    {reply, started, State#state{ slots = N-1 }};
handle_call({enqueue, Task}, _From, #state{ slots = N, queue = Q } = State) when N =< 0 ->
    Q1 = queue:in(Task, Q),
    {reply, enqueued, State#state{ queue = Q1 }};

handle_call({push, Task}, _From, State = #state{ slots = N }) when N > 0 ->
    run_worker(Task),
    {reply, ok, State#state{ slots = N-1 }};
handle_call({push, Task}, _From, #state{ slots = N, queue = Q } = State) when N =< 0 ->
    Q1 = queue:in_r(Task, Q),
    {reply, ok, State#state{ queue = Q1 }};

handle_call(is_empty_queue, _From, State = #state{ queue = Q }) ->
    {reply, queue:is_empty(Q), State};

handle_call(wait_for_queue, From, State = #state{ halted = HList, queue = Q }) ->
    case queue:is_empty(Q) of
        true -> {reply, ok, State};
        false -> {noreply, State#state{ halted = [From|HList] }}
    end;

handle_call(stop, _From, State) ->
    {stop, normal, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

-spec handle_cast(any(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(any(), #state{}) -> {noreply, #state{}}.
handle_info({'DOWN', _Ref, process, _Pid, _}, #state{ slots = N, queue = Q, halted = HList} = State) ->
    case queue:out(Q) of
        {{value, Task}, Q1} ->
            run_worker(Task),
            {noreply, State#state{ queue = Q1 }};
        {empty, Q1} ->
            lists:foreach(fun(From) -> gen_server:reply(From, ok) end, HList),
            {noreply, State#state{ slots = N+1, queue = Q1, halted = [] }}
    end;
    
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(any(), #state{}) -> any().
terminate(_Reason, _State) ->
    ok.

-spec code_change(any(), any(), any()) -> {ok, any()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

run_worker(Task) ->
    {ok, Pid} = supervisor:start_child(ejms_pool_sup, [Task]),
    _Ref = erlang:monitor(process, Pid).
