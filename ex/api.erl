-module(api).

-export([f/1, g/2]).

f(String) ->
    persist:new_f(String).

g(String, Role) when is_list(String), is_atom(Role) ->
    case String of
        [$u,$s,$e,$r|_] -> persist:new_f(String);
        _ -> error
    end.

h() ->
    spawn_link(fun k/0).

k() ->
    receive
        {f, String} ->
            persist:new_f(String),
            k();
        _ ->
            k()
    end.


