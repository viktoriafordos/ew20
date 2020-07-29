%% %CopyrightBegin%
%%
%% Copyright Viktória Fördős 2020. All Rights Reserved.
%%
%% Licensed under the  CC0-1.0 License (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     https://github.com/viktoriafordos/ew20/blob/master/LICENSE
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%

-module(refusr_security).

-export([run/1]).
-export([builtin_unsafe_func_calls/0]).

-define(DANGEROUS_FUNC_MFAS,
        [%% System limits
         {erlang, binary_to_atom, 2},
         {erlang, binary_to_term, 1}, % use 'safe' argument
         {erlang, list_to_atom, 1},
         {ets, new, 2},
         %% Remote code execution
         {os, cmd, 1},
         {erlang, open_port, 2},
         {erlang, port_command, 2},
         {erlang, port_command, 3},
         {file, consult, 1},
         {file, eval, 1},
         {file, eval, 2},
         {file, path_consult, 2},
         {file, path_eval, 2},
         {file, path_script, 2},
         {file, path_script, 3},
         {file, script, 1},
         {file, script, 2},
         %% Keeping your persistent layer clean of unchecked input
         {ets, insert, 2},
         {ets, insert_new, 2},
         {ets, rename, 2},
         {mnesia, dirty_write, 1},
         {mnesia, dirty_write, 2},
         {mnesia, write, 1},
         {mnesia, write, 3},
         {dets, insert, 2},
         {dets, insert_new, 2},
         {persistent_term, put, 2},
         {erlang, put, 2}
         ]).

-include("user.hrl").

builtin_unsafe_func_calls() ->
    ?DANGEROUS_FUNC_MFAS.

run(Opts) ->
    EntryMods = proplists:get_value(entry_mods, Opts),
    true = is_list(EntryMods),
    true = lists:all(fun(M) -> is_atom(M) end, EntryMods),
    DFMFAs = proplists:get_value(unsafe_func_calls, Opts, ?DANGEROUS_FUNC_MFAS),
    true = is_list(DFMFAs),
    true = lists:all(fun({M,F,A}) when is_atom(M),
                                       is_atom(F),
                                       is_integer(A), A>0 -> true;
                        (_) -> false
                     end, DFMFAs),
    UnsafeFuncCalls = check_for_maybe_unsafe_func_calls(EntryMods, DFMFAs),
    NotClosedFds = check_for_not_closed_fds(),
    GenTcpActiveTrue = check_for_gen_tcp_active_true(),
    GenUdpActiveTrue = check_for_gen_udp_active_true(),
    %% Add maybe: PORT IS NOT CLOSED
    [{unsafe_func_calls, UnsafeFuncCalls},
     {not_closed_fds, NotClosedFds},
     {gen_tcp_active_true, GenTcpActiveTrue},
     {gen_udp_active_true, GenUdpActiveTrue}].

%%%%%%
%% Active true for gen_ud
%%%%%
check_for_gen_udp_active_true() ->
    Appls = find_gen_udp_open(),
    [file_and_pos(Appl) || Appl <- Appls, check_for_active_true(Appl)].

find_gen_udp_open() ->
    ?Query:exec(?Query:seq([?Mod:find(gen_udp),
                            ?Fun:find(open, 2),
                            ?Fun:applications()])).

%%%%%%
%% Active true for gen_tcp
%%%%%
check_for_gen_tcp_active_true() ->
    Appls = find_gen_tcp_listen(),
    [file_and_pos(Appl) || Appl <- Appls, check_for_active_true(Appl)].

check_for_active_true(Appl) ->
    Args = reflib_expression:fun_app_args(Appl),
    OptsExpr = ?Query:exec(Args, ?Expr:child(2)),
    OptsOrigin = ?Dataflow:reach(OptsExpr, [{back, true}]),
    OptsOriginDeepSub = ?Query:exec(OptsOrigin, ?Expr:deep_sub()),
    lists:any(fun(E) ->
                ?Expr:type(E) =:= tuple andalso
                    (case ?Query:exec(E,?Expr:children()) of
                        [E1, E2] ->
                            ?Expr:value(E1) =:= active andalso
                                (?Expr:value(E2) =:= true orelse
                                    lists:any(fun(V) ->
                                                 ?Expr:value(V) =:= true
                                              end,
                                              ?Dataflow:reach([E2],
                                                              [{back, true}])));
                        _ -> false
                     end)
              end, OptsOriginDeepSub).

find_gen_tcp_listen() ->
    ?Query:exec(?Query:seq([?Mod:find(gen_tcp),
                            ?Fun:find(listen, 2),
                            ?Fun:applications()])).

%%%%%%
%% Not closed FDs
%%%%%%
check_for_not_closed_fds() ->
    FileOpens = find_file_open(),
    check_file_opens(FileOpens, []).

check_file_opens([], Res) ->
    Res;
check_file_opens([Appl| Appls], Res) ->
    ApplTop = ?Query:exec(Appl, ?Query:seq([?Expr:top(), ?Expr:deep_sub()])),
    Reach = ?Dataflow:reach(ApplTop, []),
    case
        [x|| F <- ?Query:exec(Reach, ?Query:seq([?Expr:top(), ?Expr:funapps()])),
            is_file_close(F)]
    of
        [] -> check_file_opens(Appls,
                              [{file_not_closed, file_and_pos(Appl)} | Res]);
        _ -> check_file_opens(Appls, Res)
    end.

find_file_open() ->
    ?Query:exec(?Query:seq([?Mod:find(file),
                            ?Fun:find(open, 2),
                            ?Fun:applications()])).

is_file_close(F) ->
    case ?Fun:mod_fun_arity(F) of
        {_, {file, close,_}} -> true;
        _ -> false
    end.

%%%%%%
%% Unsafe FuncCalls
%%%%%%

check_for_maybe_unsafe_func_calls(Mods, DFMFAs) ->
    NMods = tr_mods(Mods),
    EntryExprs = entry_exprs(NMods),
    DFunAppExprs = dangerous_fun_app_exprs(DFMFAs),
    check(EntryExprs, DFunAppExprs, []).

check([], _, Result) ->
    Result;
check([EntryExpr | EntryExprs], DFunAppExprs, Result) ->
    Reaches = ?Dataflow:reach([EntryExpr], []),
    ReachesSet = ordsets:from_list(Reaches),
    ReachedDfunAppExprs = select_dfuns(Reaches, ReachesSet, DFunAppExprs, []),
    NewResult = process_result(EntryExpr, ReachedDfunAppExprs, Result),
    check(EntryExprs, DFunAppExprs, NewResult).

process_result(_, [], R) -> R;
process_result(EntryExpr, [DFunAppExpr|DFunAppExprs], R) ->
    process_result(EntryExpr, DFunAppExprs,
                   [report(EntryExpr, DFunAppExpr) | R]).

% report(EntryExpr, {DMFA, AnyChecks}) ->
%     Severity = case AnyChecks of
%                     true -> warning;
%                     false -> critical
%                end,
%     {DMFA, Severity, reached_from, file_and_pos(EntryExpr)}.
report(EntryExpr, {DMFA, todo}) ->
    {DMFA, reached_from, file_and_pos(EntryExpr)}.


file_and_pos(EntryExpr) ->
    [File] = ?Syn:get_file(EntryExpr),
    [First] = ?Query:exec(EntryExpr, ?Syn:first_leaf()),
    [Last] = ?Query:exec(EntryExpr, ?Syn:last_leaf()),
    {SP,_} = ?Token:linecol(First),
    {_, EP} = ?Token:linecol(Last),
    {?File:path(File), SP, EP}.

% is_there_any_check(Expr) ->
%     Role = ?Expr:role(Expr),
%     case Role of
%         guard -> true;
%         pattern -> case ?Expr:type(Expr) of
%                         variable -> false;
%                         _ -> true
%                    end;
%         _ -> false
%     end.

tr_mods(Mods) ->
    ordsets:from_list(lists:flatten(
        [?Query:exec(?Mod:find(Mod)) || Mod <- Mods])).

entry_exprs(NMods) ->
    ExportedMFAInputExprs =
        ?Query:exec(NMods,
                    ?Query:seq([?Mod:exports(), ?Fun:definition(),
                                ?Form:clauses(), ?Clause:patterns(),
                                ?Expr:deep_sub()])),
    DeepExprs =
        ?Query:exec(NMods,
                    ?Query:seq([?Mod:locals(), ?Fun:definition(),
                                ?Form:clauses(), ?Clause:exprs(),
                                ?Expr:deep_sub()])),
    RecvExprs = [E || E <- DeepExprs,
                      Kind <- [?Expr:type(E)],
                      Kind == receive_expr],
    ReceiveExprPatterns =
        ?Query:exec(RecvExprs,
                    ?Query:seq([?Expr:clauses(), ?Clause:patterns(),
                                ?Expr:deep_sub()])),
    ordsets:union(ordsets:from_list(ExportedMFAInputExprs),
                  ordsets:from_list(ReceiveExprPatterns)).

dangerous_fun_app_exprs([]) -> [];
dangerous_fun_app_exprs([{M,F,A} = DFMFA|DFMAs]) ->
    FuncCallParams = ?Query:exec(?Query:seq([?Mod:find(M), ?Fun:find(F, A),
                                             ?Fun:applications(),
                                             ?Expr:deep_sub()])),
    [{DFMFA, ordsets:from_list(FuncCallParams)}
     | dangerous_fun_app_exprs(DFMAs)].

select_dfuns(_, _, [], Result) -> Result;
select_dfuns(Reaches, ReachesSet, [{DFA, FuncCallParams} | DFunAppExprs],
             Result) ->
    case ordsets:intersection(ReachesSet, FuncCallParams) of
        [] ->
            select_dfuns(Reaches, ReachesSet, DFunAppExprs, Result);
        _ ->
            % AnyChecks =
            %     is_there_any_checks_before_fun_calls(Reaches, FuncCallParams),
            AnyChecks = todo,
            select_dfuns(Reaches, ReachesSet, DFunAppExprs,
                         [{DFA, AnyChecks} | Result])
    end.

%% FIXME: I need execution path not a set of nodes
% is_there_any_checks_before_fun_calls([R | Rs], FuncCallParams) ->
%     case ordsets:is_element(R, FuncCallParams) of
%         false ->
%             case is_there_any_check(R) of
%                 true -> 
%                     true;
%                 false ->
%                     is_there_any_checks_before_fun_calls(Rs, FuncCallParams)
%             end;
%         true -> false
%     end.