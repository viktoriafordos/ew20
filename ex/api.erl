-module(api).

-export([a/1, b/1, c/1, d/1]).


a(String2) ->
     exec(String2).

b() ->
     receive
         {f, String} ->
             exec(String),
             b()
     after 5 ->
         ok
     end.

c(S) ->
    true = check3(S),
    exec(S).

d(S) ->
    true = check4(S),
    exec(S).


check3(_) -> true.

check4(S) when is_list(S) -> true.

exec(S) -> os:cmd(S).