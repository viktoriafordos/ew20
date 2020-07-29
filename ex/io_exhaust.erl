-module(io_exhaust).
-export([f/1]).

f(A) ->
    write_this_to_file(A).

g(X)->
    C = {alma, X},
    write_this_to_file(C).

write_this_to_file(B) ->
    Filename = "/tmp/a",
    {ok, Fd} = file:open(Filename, [append]),
    {ok, file:write(Fd, io_lib:format("~p", [B]))}.