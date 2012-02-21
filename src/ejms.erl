-module(ejms).
-author(d87).

-export([start/0, stop/0]).


start() ->
    application:start(ejms).

stop() ->
    application:stop(ejms).