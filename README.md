# ew20
Prototype implementation of the security analysis introduced in V. Fördős: Secure Design and Verification of Erlang Systems paper.

```
ACM Reference Format:
Viktória Fördős. 2020. Secure Design and Verification of Erlang Systems. In Proceedings of the 19th ACM SIGPLAN International Workshop on Erlang (Erlang ’20), August 23, 2020, Virtual Event, USA. ACM, New York, NY, USA, 10 pages. https://doi.org/10.1145/ 3406085.3409011
```

## Disclaimer

The author accepts no responsibility for errors not found by the prototype. The prototype has been reasonably well tested, but the possibility of errors remains.


## Using the prototype

To build the project, enter the `ew20` directory and run:

```
ew20$ make build
```

To get a RefactorErl shell (depends on a successful build), run:

```
ew20$ make start
```

To run security analysis, the Erlang modules of a trust zone need to be loaded into RefactorErl first.
Use `ri:addenv/2` to set up your environment and `ri:add/{1,2}` to add your files.
Read more about [managing your files and applications in RefactorErl](http://pnyf.inf.elte.hu/trac/refactorerl/wiki/ManagingFiles) in [RefactorErl's official guide](http://pnyf.inf.elte.hu/trac/refactorerl/wiki).

Then, in the RefactorErl's shell, start the analysis:

```erlang
(refactorerl@localhost)2> refusr_security:run([{entry_mods, [mod1, mod2]}]).
[{unsafe_func_calls,[]},
 {not_closed_fds,[]},
 {gen_tcp_active_true,[]},
 {gen_udp_active_true,[]}]
```

The input of the analysis are the entry modules of the trust zone. In the above example we have two entry modules: `mod1` and `mod2`.

The output of the analysis are the findings:

* If data entering the trust zone through the entry modules reaches any listed vulnerabilities (see `refusr_security:builtin_unsafe_func_calls/0`) the prototype outputs the file and position information of the entry expression and the reached vulnerable function under `unsafe_func_calls`.
* The prototype finds not closed file descriptors and outputs them under `not_closed_fds`.
* The prototype finds TCP and UDP servers started in forever active mode and outputs them under `gen_tcp_active_true` and `gen_udp_active_true`.

## Example

Under the `ex` folder, you can find very basic example modules to play with the prototype.

After successfully building the tool, do:

```
ew20$ make start
cd referl && bin/referl
Erlang/OTP 22 [erts-10.7.1] [source] [64-bit] [smp:12:12] [ds:12:12:10] [async-threads:1] [hipe]
Eshell V10.7.1  (abort with ^G)
(refactorerl@localhost)1> ri:add("../ex").
| 1.18 kB/s >>>>>>>>>>>>>>>>>>>| [   6/   6] api.erl
| 1.38 kB/s >>>>>>>>>>>>>>>>>>>| [   6/   6] better_api.erl
| 1.50 kB/s >>>>>>>>>>>>>>>>>>>| [   5/   5] io_exhaust.erl
| 1.58 kB/s >>>>>>>>>>>>>>>>>>>| [   5/   5] persist.erl
| 1.22 kB/s >>>>>>>>>>>>>>>>>>>| [   4/   4] tcp_ex.erl
ok
(refactorerl@localhost)2> refusr_security:run([{entry_mods, [api, better_api]}]).
[{unsafe_func_calls,[{{os,cmd,1},
                      reached_from,
                      {"ew20/ex/better_api.erl",
                       {19,13},
                       {19,18}}},
                     {{os,cmd,1},
                      reached_from,
                      {"ew20/ex/better_api.erl",
                       {8,3},
                       {8,8}}},
                     {{os,cmd,1},
                      reached_from,
                      {"ew20/ex/better_api.erl",
                       {5,3},
                       {5,8}}},
                     {{os,cmd,1},
                      reached_from,
                      {"ew20/ex/api.erl",
                       {19,13},
                       {19,18}}},
                     {{os,cmd,1},
                      reached_from,
                      {"ew20/ex/api.erl",
                       {8,3},
                       {8,8}}},
                     {{os,cmd,1},
                      reached_from,
                      {"ew20/ex/api.erl",
                       {5,3},
                       {5,8}}}]},
 {not_closed_fds,[{file_not_closed,{"ew20/ex/io_exhaust.erl",
                                    {13,16},
                                    {13,44}}}]},
 {gen_tcp_active_true,[{"ew20/ex/tcp_ex.erl",
                        {4,19},
                        {5,56}},
                       {"ew20/ex/tcp_ex.erl",
                        {15,19},
                        {15,44}}]},
 {gen_udp_active_true,[]}]
(refactorerl@localhost)3>
```