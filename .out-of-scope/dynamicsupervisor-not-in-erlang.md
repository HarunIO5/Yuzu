# DynamicSupervisor migration (Erlang gateway)

This project's gateway (`gateway/apps/yuzu_gw/`) is a plain Erlang/OTP (rebar3) application. It does not use Elixir, Mix, or any Elixir library — so **Elixir's `DynamicSupervisor` module is not available here and never will be** unless the gateway is rewritten in Elixir.

## Why this is out of scope

`DynamicSupervisor` is an Elixir-level abstraction built on top of Erlang's `simple_one_for_one` supervisor strategy. It was introduced in Elixir to give a nicer API around dynamic child management (per-child `start_child`, `max_children`, `extra_arguments`, etc.), and Elixir tooling now flags `:simple_one_for_one` as the "old way" *within Elixir*.

In vanilla Erlang/OTP, there is no separate "modern dynamic supervisor" module. `simple_one_for_one` remains the standard, fully-supported strategy in the `supervisor` behaviour (confirmed current as of OTP 28/29 documentation) for supervising a dynamically-started pool of homogeneous child processes — which is exactly what `yuzu_gw_agent_sup.erl` does (one process per connected agent, started on demand via `supervisor:start_child(?SERVER, [Args])`).

The gateway's supervisor already uses the modern (OTP 18+) map-based `sup_flags`/child-spec return from `init/1` — it is not using some deprecated pre-map-spec form. There is no concrete migration target to move to.

```erlang
%% Current, correct-for-Erlang shape (yuzu_gw_agent_sup.erl):
init([]) ->
    SupFlags = #{strategy => simple_one_for_one, intensity => 10, period => 60},
    ChildSpec = #{id => yuzu_gw_agent, start => {yuzu_gw_agent, start_link, []}, restart => transient},
    {ok, {SupFlags, [ChildSpec]}}.
```

The legitimate concern hiding behind this request — that a single `simple_one_for_one` supervisor managing very large numbers of dynamic children (millions of agents) can become an operational bottleneck (one process owning the whole child list) — is real, but the fix is **sharding into multiple supervisors** (see the cell-based topology / hierarchical fanout proposals in the gateway-scalability workstream), not switching supervisor behaviours. Erlang has no built-in construct that solves this differently than plain multiplication of `simple_one_for_one` trees.

## Prior requests

- #127 — "[Gateway] Migrate from simple_one_for_one to modern dynamic supervision"
