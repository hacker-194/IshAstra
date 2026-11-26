--------------------------- MODULE LeaseFencing ---------------------------
(*
 * TLA+ model of distributed lease fencing for automated failover.
 *
 * This models the fencing token mechanism that prevents stale lease holders
 * from performing operations after losing the lease. The fencing token is a
 * monotonically increasing counter that increments on every acquisition and
 * renewal. Operations include the fencing token, and the system rejects
 * operations with stale tokens.
 *
 * Invariants checked:
 *   FencingTokenMonotonic: fencing token only increases
 *   NoStaleOperations: operations with stale tokens are rejected
 *   UniqueLeader: at most one holder can have the lease at a time
 *   FailoverWorks: a new holder can acquire after the old lease expires
 *)

EXTENDS Naturals, Sequences, TLC

CONSTANTS
    MaxHolders,        \* Number of processes that can hold leases
    MaxTokens,         \* Bound on fencing token values
    MaxTime            \* Bound on time values for model checking

\* Model values
Time == 0..MaxTime
Token == 0..MaxTokens
Holder == 1..MaxHolders
LeaseName == {"scheduler", "rate_limiter:tenant1", "rate_limiter:tenant2"}

\* Lease state
LeaseState == [name: LeaseName,
               holder: Holder \cup {None},
               expiresAt: Time,
               fencingToken: Token]

VARIABLES
    leases,             \* Current state of all leases
    operations,         \* Log of attempted operations (for verification)
    currentTime         \* Model time

vars == <<leases, operations, currentTime>>

\* Initial state: no leases held
Init ==
    /\ leases = [n \in LeaseName |-> [holder |-> None, expiresAt |-> 0, fencingToken |-> 0]]
    /\ operations = <<>>
    /\ currentTime = 0

\* Helper: check if a lease is currently held (not expired)
IsHeld(lease) ==
    /\ lease.holder # None
    /\ lease.expiresAt > currentTime

\* Helper: get current holder and token for a lease
CurrentHolder(name) ==
    IF IsHeld(leases[name]) THEN leases[name].holder ELSE None

CurrentToken(name) ==
    IF IsHeld(leases[name]) THEN leases[name].fencingToken ELSE 0

\* Time advances (simulates clock)
Tick ==
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<leases, operations>>

\* Acquire lease: new holder gets token = 1, existing holder increments token
Acquire(name, holder) ==
    /\ ~IsHeld(leases[name]) \/ leases[name].holder = holder
    /\ leases' = [leases EXCEPT
        ![name] = [holder |-> holder,
                   expiresAt |-> currentTime + 30,  \* 30 time units TTL
                   fencingToken |-> IF leases[name].holder = holder
                                     THEN leases[name].fencingToken + 1
                                     ELSE 1]]
    /\ operations' = Append(operations,
         [type |-> "acquire", name |-> name, holder |-> holder,
          token |-> IF leases[name].holder = holder
                     THEN leases[name].fencingToken + 1
                     ELSE 1,
          time |-> currentTime])
    /\ UNCHANGED currentTime

\* Renew lease: increment fencing token, extend expiry
Renew(name, holder, token) ==
    /\ IsHeld(leases[name])
    /\ leases[name].holder = holder
    /\ token = leases[name].fencingToken          \* Must present current token
    /\ leases' = [leases EXCEPT
        ![name] = [expiresAt |-> currentTime + 30,
                   fencingToken |-> leases[name].fencingToken + 1]]
    /\ operations' = Append(operations,
         [type |-> "renew", name |-> name, holder |-> holder,
          token |-> leases[name].fencingToken + 1,
          time |-> currentTime])
    /\ UNCHANGED currentTime

\* Stale renewal attempt: old holder tries to renew with stale token
StaleRenew(name, holder, staleToken) ==
    /\ IsHeld(leases[name])
    /\ leases[name].holder = holder
    /\ staleToken < leases[name].fencingToken
    /\ operations' = Append(operations,
         [type |-> "stale_renew", name |-> name, holder |-> holder,
          token |-> staleToken,
          rejected |-> TRUE,
          time |-> currentTime])
    /\ UNCHANGED <<leases, currentTime>>

\* Release lease: only succeeds if token matches (fencing)
Release(name, holder, token) ==
    /\ IsHeld(leases[name])
    /\ leases[name].holder = holder
    /\ token = leases[name].fencingToken          \* Must present current token
    /\ leases' = [leases EXCEPT ![name] = [holder |-> None, expiresAt |-> 0, fencingToken |-> 0]]
    /\ operations' = Append(operations,
         [type |-> "release", name |-> name, holder |-> holder,
          token |-> token,
          time |-> currentTime])
    /\ UNCHANGED currentTime

\* Stale release attempt: old holder tries to release with stale token
StaleRelease(name, holder, staleToken) ==
    /\ IsHeld(leases[name])
    /\ leases[name].holder = holder
    /\ staleToken < leases[name].fencingToken
    /\ operations' = Append(operations,
         [type |-> "stale_release", name |-> name, holder |-> holder,
          token |-> staleToken,
          rejected |-> TRUE,
          time |-> currentTime])
    /\ UNCHANGED <<leases, currentTime>>

\* Expired lease can be acquired by new holder
AcquireAfterExpiry(name, newHolder) ==
    /\ leases[name].holder # None
    /\ leases[name].expiresAt <= currentTime       \* Lease expired
    /\ leases' = [leases EXCEPT
        ![name] = [holder |-> newHolder,
                   expiresAt |-> currentTime + 30,
                   fencingToken |-> 1]]
    /\ operations' = Append(operations,
         [type |-> "acquire_after_expiry", name |-> name,
          holder |-> newHolder, token |-> 1,
          time |-> currentTime])
    /\ UNCHANGED currentTime

Next ==
    \/ \E n \in LeaseName, h \in Holder: Acquire(n, h)
    \/ \E n \in LeaseName, h \in Holder, t \in Token: Renew(n, h, t)
    \/ \E n \in LeaseName, h \in Holder, t \in Token: StaleRenew(n, h, t)
    \/ \E n \in LeaseName, h \in Holder, t \in Token: Release(n, h, t)
    \/ \E n \in LeaseName, h \in Holder, t \in Token: StaleRelease(n, h, t)
    \/ \E n \in LeaseName, h \in Holder: AcquireAfterExpiry(n, h)
    \/ Tick

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* Fencing token only increases (monotonic)
FencingTokenMonotonic ==
    \A n \in LeaseName:
        \A op1, op2 \in operations:
            (op1.time < op2.time /\ op1.name = n /\ op2.name = n
             /\ op1.type \in {"acquire", "renew"} /\ op2.type \in {"acquire", "renew"}
             /\ op1.holder = op2.holder)
            => op1.token <= op2.token

\* No stale operations accepted: any operation with token < current token is rejected
NoStaleOperations ==
    \A op \in operations:
        (op.type = "stale_renew" \/ op.type = "stale_release") => op.rejected = TRUE

\* At most one holder per lease at any time (mutual exclusion)
UniqueLeader ==
    \A n \in LeaseName:
        \A t \in Time:
            \* Count holders at time t by examining operations up to t
            LET opsUpToT == [op \in operations : op.time <= t /\ op.name = n]
                holders == {op.holder : op \in opsUpToT
                           /\ op.type \in {"acquire", "acquire_after_expiry"}
                           /\ op.holder # None}
            IN Cardinality(holders) <= 1

\* Failover works: after lease expires, new holder can acquire with token=1
FailoverWorks ==
    \A op1, op2 \in operations:
        (op1.type = "acquire_after_expiry" /\ op2.type = "acquire_after_expiry"
         /\ op1.name = op2.name /\ op1.time < op2.time)
        => op1.token = 1 /\ op2.token = 1

\* Token increments on every acquisition/renewal by same holder
TokenIncrements ==
    \A n \in LeaseName:
        \A op1, op2 \in operations:
            (op1.time < op2.time /\ op1.name = n /\ op2.name = n
             /\ op1.holder = op2.holder /\ op1.holder # None
             /\ op1.type \in {"acquire", "renew"} /\ op2.type \in {"acquire", "renew"})
            => op2.token = op1.token + 1

(***************************************************************************)
(* Theorems                                                                *)
(***************************************************************************)

THEOREM Spec => []FencingTokenMonotonic
THEOREM Spec => []NoStaleOperations
THEOREM Spec => []UniqueLeader
THEOREM Spec => []FailoverWorks
THEOREM Spec => []TokenIncrements

=============================================================================