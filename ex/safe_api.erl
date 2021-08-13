-module(safe_api).

-export([a/1, b/1, c/1, d/1, e/1, f/1]).

a(String2) ->
     [$u,$s,$e,$r|_] = String2,
     persist:new_f(String2).

b(String, Role) when is_list(String), is_atom(Role) ->
     case String of
         [$u,$s,$e,$r|_] -> persist:new_f(String);
         _ -> error
     end.

c(S) ->
    [$u,$s,$e,$r|_] = S,
    4 = inc2(inc(1)),
    persist:new_f(S),
    ok.

d(S) ->
    check(S),
    4 = inc2(inc(1)),
    persist:new_f(S),
    ok.

e(S) ->
    true = check2(S),
    4 = inc2(inc(1)),
    persist:new_f(S),
    ok.

f(S) ->
    X = {user, S},
    true = check3(X),
    4 = inc2(inc(1)),
    persist:new_f(S),
    ok.

check(S) ->
    [$u,$s,$e,$r|_] = S.

check2([$u,$s,$e,$r|_]) -> true;
check2(_) -> false.

check3({_,[$u,$s,$e,$r|_]}) -> true;
check3(_) -> false.

inc(E) -> X = E+1, X.

inc2(G) -> X = G +2, X.
