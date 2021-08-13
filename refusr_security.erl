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
         %% Remote code execution (bash injection)
         {os, cmd, 1},
         {erlang, open_port, 2},
         {erlang, port_command, 2},
         {erlang, port_command, 3},
         {os, putenv, 2},
         {os, unsetenv, 1},
         %% Remote code execution (Erlang code)
         {file, consult, 1},
         {file, eval, 1},
         {file, eval, 2},
         {file, path_consult, 2},
         {file, path_eval, 2},
         {file, path_script, 2},
         {file, path_script, 3},
         {file, script, 1},
         {file, script, 2},
         %% Path traversal
         {filelib, wildcard, 1},
         {filelib, wildcard, 2},
         {file, path_open, 3},
         {file, del_dir, 1},
         {file, del_dir_r, 1},
         {file, list_dir, 1},
         {file, list_dir_all, 1},
         {file, make_dir, 1},
         {file, open, 2},
         {file, delete, 1},
         {file, delete, 2},
         {file, read_file, 1},
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

-define(TYPE_TESTS,
        [{erlang, is_atom, 1},
         {erlang, is_binary, 1},
         {erlang, is_bitstring, 1},
         {erlang, is_boolean, 1},
         {erlang, is_float, 1},
         {erlang, is_function, 1},
         {erlang, is_function, 2},
         {erlang, is_integer, 1},
         {erlang, is_list, 1},
         {erlang, is_map, 1},
         {erlang, is_number, 1},
         {erlang, is_pid, 1},
         {erlang, is_port, 1},
         {erlang, is_record, 2},
         {erlang, is_record, 3},
         {erlang, is_reference, 1},
         {erlang, is_tuple, 1}]).


-include("user.hrl").

builtin_unsafe_func_calls() ->
    ?DANGEROUS_FUNC_MFAS.

run(Opts) ->
    EntryMods = proplists:get_value(entry_mods, Opts),
    EMFA = proplists:get_value(mfa, Opts),
    true = (is_list(EntryMods) andalso lists:all(fun is_atom/1, EntryMods))
                    orelse (is_tuple(EMFA) andalso is_mfa(EMFA)),
    DFMFAs = proplists:get_value(unsafe_func_calls, Opts, ?DANGEROUS_FUNC_MFAS),
    true = is_list(DFMFAs),
    true = lists:all(fun is_mfa/1, DFMFAs),
    IsOrdered0 = proplists:get_value(ordered, Opts, false),
    IsOrdered = ensure_referl_slicer_started(IsOrdered0),
    true = is_boolean(IsOrdered),
    UnsafeFuncCalls =
        check_for_maybe_unsafe_func_calls(EntryMods, EMFA, DFMFAs, IsOrdered),
    NotClosedFds = check_for_not_closed_fds(),
    GenTcpActiveTrue = check_for_gen_tcp_active_true(),
    GenUdpActiveTrue = check_for_gen_udp_active_true(),
    [{unsafe_func_calls, UnsafeFuncCalls},
     {not_closed_fds, NotClosedFds},
     {gen_tcp_active_true, GenTcpActiveTrue},
     {gen_udp_active_true, GenUdpActiveTrue}].

is_mfa({M,F,A}) when is_atom(M), is_atom(F), is_integer(A), A>0 -> true;
is_mfa(_) -> false.

%% Terrible hack to start the referl_slicer application :(
ensure_referl_slicer_started(false) -> false;
ensure_referl_slicer_started(true) ->
    case is_referl_slicer_started() of
        error -> error;
        true -> true;
        false ->
            Self = self(),
            %% FIXME: fix startup problem of referl_slicer
            spawn(fun()-> process_flag(trap_exit, true),
                          refsc_sup:start(normal,[]),
                          Self ! started,
                          receive ok -> ok end
                  end),
            receive
                started -> ok
            after
                500 -> ok
            end,
            is_referl_slicer_started()
    end.

is_referl_slicer_started() ->
    case whereis(refsc_cfg_server) of
        Pid when is_pid(Pid) -> true;
        undefined ->
            case lists:keyfind(referl_slicer, 1,
                               application:which_applications()) of
                false -> error;
                _ -> false
            end
    end.


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

find_gen_tcp_recv() ->
    ?Query:exec(?Query:seq([?Mod:find(gen_tcp),
                            ?Fun:find(recv, 3),
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

check_for_maybe_unsafe_func_calls(undefined, {M, F, A}, DFMFAs, IsOrdered) ->
    EntryExprs = entry_exprs(M, F, A),
    DFunAppExprs = dangerous_fun_app_exprs(DFMFAs),
    order_results(check(EntryExprs, DFunAppExprs, IsOrdered), IsOrdered);
check_for_maybe_unsafe_func_calls(Mods, undefined, DFMFAs, IsOrdered) ->
    NMods = tr_mods(Mods),
    EntryExprs = entry_exprs(NMods),
    DFunAppExprs = dangerous_fun_app_exprs(DFMFAs),
    order_results(check(EntryExprs, DFunAppExprs, IsOrdered), IsOrdered).

order_results(Results, false) -> Results;
order_results(Results, true) -> lists:keysort(2, Results).

check(EntryExprs, DFunAppExprs, IsOrdered) ->
    {WorkerCnt, Chunks} = chunks(EntryExprs),
    Receiver = self(),
    process_flag(trap_exit, true),
    [spawn_link(fun() ->
                    Receiver ! {result,
                                check(Chunk, DFunAppExprs, IsOrdered, [])}
                end) || Chunk <- Chunks],
    receive_results(WorkerCnt, []).

receive_results(0, Results) -> lists:append(Results);
receive_results(Cnt, Results0) ->
    receive
        {result, Result} ->
            receive_results(Cnt - 1, [Result |Results0]);
        {'EXIT', _, normal} ->
            receive_results(Cnt, Results0);
        {'EXIT', _, _} ->
            receive_results(Cnt - 1, Results0)
    end.

chunks(EntryExprs) ->
    SchedulersOnline = erlang:system_info(schedulers_online),
    chunks(EntryExprs,
           SchedulersOnline,
           length(EntryExprs) div SchedulersOnline).

chunks(EntryExprs, WorkerCnt, ChunkSize) when ChunkSize < 5; WorkerCnt =:= 1 ->
    {1, [EntryExprs]};
chunks(EntryExprs, WorkerCnt, ChunkSize) ->
    {WorkerCnt, chunks(EntryExprs, WorkerCnt, ChunkSize, [])}.

chunks(EntryExprs0, 1, _ChunkSize, Chunks) ->
    [EntryExprs0|Chunks];
chunks(EntryExprs0, WorkerCnt, ChunkSize, Chunks) ->
    {Chunk, EntryExprs} = lists:split(ChunkSize, EntryExprs0),
    chunks(EntryExprs, WorkerCnt - 1, ChunkSize, [Chunk | Chunks]).


check([], _, _, Result) ->
    Result;
check([EntryExpr | EntryExprs], DFunAppExprs, IsOrdered, Result) ->
    Reaches = ordsets:from_list(?Dataflow:reach([EntryExpr], [])),
    ReachedDfunAppExprs = select_dfuns(EntryExpr, Reaches, DFunAppExprs,
                                       IsOrdered, []),
    NewResult = process_result(EntryExpr, ReachedDfunAppExprs, Result),
    check(EntryExprs, DFunAppExprs, IsOrdered, NewResult).

process_result(_, [], R) -> R;
process_result(EntryExpr, [DFunAppExpr|DFunAppExprs], R) ->
    process_result(EntryExpr, DFunAppExprs,
                   [report(EntryExpr, DFunAppExpr) | R]).

report(EntryExpr, {DMFA, no_check}) ->
    {DMFA, reached_from, file_and_pos(EntryExpr)};
report(EntryExpr, {DMFA, AnyChecks}) ->
    Severity = case AnyChecks of
                    true -> warning;
                    false -> critical
               end,
    {DMFA, Severity, reached_from, file_and_pos(EntryExpr)}.

file_and_pos(EntryExpr) ->
    [File] = ?Syn:get_file(EntryExpr),
    [First] = ?Query:exec(EntryExpr, ?Syn:first_leaf()),
    [Last] = ?Query:exec(EntryExpr, ?Syn:last_leaf()),
    {SP,_} = ?Token:linecol(First),
    {_, EP} = ?Token:linecol(Last),
    {?File:path(File), SP, EP}.

tr_mods(Mods) ->
    ordsets:from_list(lists:flatten(
        [?Query:exec(?Mod:find(Mod)) || Mod <- Mods])).

entry_exprs(NMods) ->
    ExportedMFAInputExprs =
        [E || E <- ?Query:exec(NMods,
                               ?Query:seq([?Mod:exports(), ?Fun:definition(),
                                           ?Form:clauses(), ?Clause:patterns(),
                                           ?Expr:deep_sub()])),
              ?Expr:type(E) =:= variable],
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
    GenTcpRecvExprs = find_gen_tcp_recv(),

    ordsets:union([ordsets:from_list(ExportedMFAInputExprs),
                   ordsets:from_list(ReceiveExprPatterns),
                   ordsets:from_list(GenTcpRecvExprs)]).

entry_exprs(M, F, A) ->
    [E || E <- ?Query:exec(?Query:seq([?Mod:find(M),
                            ?Fun:find(F, A),
                            ?Fun:definition(),
                            ?Form:clauses(), ?Clause:patterns(),
                            ?Expr:deep_sub()])),
          ?Expr:type(E) =:= variable].

dangerous_fun_app_exprs([]) -> [];
dangerous_fun_app_exprs([{M,F,A} = DFMFA|DFMAs]) ->
    FuncCallParams = ?Query:exec(?Query:seq([?Mod:find(M), ?Fun:find(F, A),
                                             ?Fun:applications(),
                                             ?Expr:deep_sub()])),
    [{DFMFA, ordsets:from_list(FuncCallParams)}
     | dangerous_fun_app_exprs(DFMAs)].

select_dfuns(_, _, [], _IsOrdered, Result) -> Result;
select_dfuns(EntryExpr, Reaches, [{DFA, FuncCallParams} | DFunAppExprs],
             IsOrdered, Result) ->
    case ordsets:intersection(Reaches, FuncCallParams) of
        [] ->
            select_dfuns(EntryExpr, Reaches, DFunAppExprs, IsOrdered, Result);
        Reached when IsOrdered ->
            AnyChecks = is_there_any_checks_before_fun_calls00(EntryExpr,
                                                               Reaches,
                                                               Reached),
            select_dfuns(EntryExpr, Reaches, DFunAppExprs, IsOrdered,
                         [{DFA, AnyChecks} | Result]);
        _ ->
            AnyChecks = no_check,
            select_dfuns(EntryExpr, Reaches, DFunAppExprs, IsOrdered,
                         [{DFA, AnyChecks} | Result])
    end.

is_there_any_checks_before_fun_calls00(EntryExpr, Reaches, Reached) ->
    try
        is_there_any_checks_before_fun_calls0(EntryExpr, Reaches, Reached)
    catch
        %% we failed to calculate the priority,
        %% the best we can do is to mark it as critical
        _Cl:_E -> false
    end.

is_there_any_checks_before_fun_calls0(_, _, []) -> true;
is_there_any_checks_before_fun_calls0(EntryExpr, Reaches,
                                      [Reached | ReachedT]) ->
    is_there_any_checks_before_fun_calls(EntryExpr, Reaches, Reached)
        andalso is_there_any_checks_before_fun_calls0(EntryExpr, Reaches,
                                                      ReachedT).

is_there_any_checks_before_fun_calls(EntryExpr, Reaches, Reached) ->
    [EntryForm] = ?Query:exec([EntryExpr],
                        ?Query:seq([?Expr:clause(), ?Clause:form()])),
    [EndForm] =  ?Query:exec([Reached],
                        ?Query:seq([?Expr:clause(), ?Clause:form()])),
    Forms = lists:usort(?Query:exec([EntryExpr |Reaches],
                        ?Query:seq([?Expr:clause(), ?Clause:form()]))),

    ok = refsc_cfg_server:build_cfgs(Forms),
    Gs = prepare_graphs(Forms, Forms, #{}),
    try
        walk_cfgs(Reached, EntryForm, maps:get(EndForm, Gs), Gs, Reaches,
                  Forms, _Visited = [])
    after
        maps:fold(fun(_Form, G, _) ->
                        %% Not all values are digraphs
                        (not is_list(G)) andalso digraph:delete(G)
                  end, ok, Gs)
    end.

prepare_graphs(_AllForms, [] = _Forms, GM) -> GM;
prepare_graphs(AllForms, [Form | Forms], GM) ->
    {Form, Edges, AppNodes} = refsc_cfg_server:get_cfg(Form),
    prepare_graphs(AllForms,
                   Forms,
                   resolve_appnodes(AllForms,
                                    GM#{Form => prepare_graph(Edges)},
                                    AppNodes)).

resolve_appnodes(_AllForms, GM, []) -> GM;
resolve_appnodes(AllForms, GM, [AppNode | AppNodes]) ->
    Resolved = lists:filter(fun(Form) ->
                                lists:member(Form, AllForms)
                            end,
                            ?Query:exec(AppNode,
                                        ?Query:seq([?Expr:ambdynfunction(),
                                                    ?Fun:definition()]))),
    resolve_appnodes(AllForms, GM#{AppNode => Resolved}, AppNodes).

prepare_graph(Edges) ->
    G = digraph:new(),
    {Ins,Outs,_} = lists:unzip3(Edges),
    [digraph:add_vertex(G, V) || V <- lists:usort(Ins)],
    [digraph:add_vertex(G, V) || V <- lists:usort(Outs)],
    [digraph:add_edge(G, V1, V2) || {V1, V2, _} <- Edges],
    G.

walk_cfgs(TN, TN, _G, _Gs, _Reaches, _Forms, _Visited) -> false;
walk_cfgs({'$gn',form, _} = N, TN, _G, Gs, Reaches, Forms, Visited) ->
    %% Finished scanning a fun definition form but found no checks.
    %% Keep going in the fun def that called this one.
    {'$gn',expr, _} = Expr = maps:fold(fun(Key, Val, Acc) ->
                                            case Val =:= [N] of
                                                true -> Key;
                                                _ -> Acc
                                            end
                                        end, not_found, Gs),
    [Form] = ?Query:exec([Expr], ?Query:seq([?Expr:clause(), ?Clause:form()])),
    walk_cfgs(Expr, TN, maps:get(Form, Gs), Gs, Reaches, Forms, Visited);
walk_cfgs(N, TN, G, Gs, Reaches, Forms, Visited) ->
    NewN = not ordsets:is_element(N, Visited),
    case  NewN andalso is_there_any_relevant_check(N, Reaches) of
        true -> true;
        false when NewN ->
            case maps:get(N, Gs, []) of
                [Form] ->
                    %% Check the fun def for checks and if there is no check
                    %% in the fun def keep going up
                    NewG = maps:get(Form, Gs),
                    walk_cfgs({ret, Form}, Form, NewG, Gs, Reaches, Forms,
                              ordsets:add_element(N, Visited)) orelse
                        combine_walk0(digraph:in_neighbours(G, N), TN, G, Gs,
                                      Reaches, Forms,
                                      ordsets:add_element(N, Visited));
                [] ->
                    %% keep going up
                    combine_walk0(digraph:in_neighbours(G, N), TN, G, Gs,
                                  Reaches, Forms,
                                  ordsets:add_element(N, Visited))
            end;
        false -> false
    end.

combine_walk0([], _TN, _G, _Gs, _Reaches, _Forms, _Visited) -> false; %% Root
combine_walk0(Ns, TN, G, Gs, Reaches, Forms, Visited) ->
    combine_walk(Ns, TN, G, Gs, Reaches, Forms, Visited).

combine_walk([], _TN, _G, _Gs, _Reaches, _Forms, _Visited) -> true;
combine_walk([N|Ns], TN, G, Gs, Reaches, Forms, Visited) ->
    %% Node with multiple parents, all parents should have checks as there
    %% were no checks found before
    walk_cfgs(N, TN, G, Gs, Reaches, Forms, Visited) andalso
        combine_walk(Ns, TN, G, Gs, Reaches, Forms, Visited).

is_there_any_relevant_check({'$gn',expr,_} = N0, Reaches) ->
    %% is_list(S) is in CFG but S is in the reach set.
    %%  {_,[$u,$s,$e,$r|_]} is in CFG but [$u,$s,$e,$r|_] is in the reach set
    Ns = ?Query:exec(N0, ?Query:seq([?Expr:top(), ?Expr:top_deep_sub()])),
    lists:any(fun(N) ->
                ordsets:is_element(N, Reaches) andalso is_there_any_check(N)
              end, Ns);
is_there_any_relevant_check(_N, _Reaches) -> false.

is_there_any_check(Expr) ->
    Role = ?Expr:role(Expr),
    case Role of
        guard -> not_only_type_tests(Expr);
        pattern -> case ?Expr:type(Expr) of
                        variable -> false;
                        joker -> false;
                        _ -> true
                   end;
        _ -> false
    end.

not_only_type_tests(Expr) ->
    [F || F <- ?Query:exec(Expr, ?Expr:functions()),
          not type_test(F)] =/= [].

type_test(F) ->
    MFA = {?Mod:name(hd(?Query:exec(F, ?Fun:module()))),
           ?Fun:name(F),
           ?Fun:arity(F)},
    list:member(MFA, ?TYPE_TESTS).
