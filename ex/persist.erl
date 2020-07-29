-module(persist).

-export([new_f/1, new_f_safe/1]).

new_f(User) ->
    os:cmd("mkdir "++User).

new_f_safe(User) when is_list(User) ->
    new_f_safe0(User).

new_f_safe0([$u,$s,$e,$r|_] = User) ->
    os:cmd("mkdir "++User).