-------------------------- MODULE JudgeAddresses --------------------------
(*
 * Bounded TLA+ model of the address policy in src/strix/core/scope.py:
 *   Scope._gate, Scope._judge_addresses, Scope._judge_intel,
 *   Scope.inherited_from  (+ _pattern_covers, _intersect_values,
 *   _intersect_networks, _earlier_expiry)
 *
 * Addresses and scopes are abstract: one record per interesting combination
 * of the properties the Python code actually reads (see AddressPool,
 * ScopeConfigs, PolicyConfigs).  Every set in this module is finite and no
 * action counts, so the reachable state space is finite and TLC terminates.
 *
 * There is deliberately no CHOOSE over a possibly-empty set: SetToSeq guards
 * its CHOOSE with S # {} (an unguarded one is what produced the earlier
 * "non-enumerable quantifier bound" failure).
 *
 * Invariants checked (JudgeAddresses.cfg):
 *   NarrowingInvariant          inherited scope never allows more than the parent
 *   ExpiryInvariant             a revoked/expired scope never allows
 *   PinInvariant                a pinned destination came from a validated set
 *   DefaultDenyInvariant        an empty include denies everything
 *   SpecialUseInvariant         allowed => every special address was authorized
 *   AuthorizedNetworkInvariant  authorized-network + intel-ok => allowed
 *)

EXTENDS Naturals, Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxAddresses    \* bound on Len(resolution)

(***************************************************************************)
(* Model constants                                                         *)
(***************************************************************************)

\* Expiry is abstracted to three model values rather than ISO timestamps
\* because TLC has no ordering on strings.  "none" = no expiry is set;
\* rank 2 (latest) is what makes _earlier_expiry skip an unset stamp.
Timestamps == {"past", "future", "none"}
TimestampRank == [past |-> 0, future |-> 1, none |-> 2]

TargetPort == 443               \* the port every request is judged for

PortUniverse == {80, 443}
AsnUniverse == {1, 2}
CountryUniverse == {"NP", "US"}

\* n2 is a subnet of n1 (stands in for ipaddress subnet_of on CIDRs)
Narrows(inner, outer) == inner = outer \/ (inner = "n2" /\ outer = "n1")

InternalSuffixes == {".localhost", ".local", ".internal", ".home.arpa"}

Hosts == {"a.example", "blocked.example", "localhost"}

(***************************************************************************)
(* Records                                                                 *)
(***************************************************************************)

\* special        = is_special_use(address)
\* embedded       = embedded_is_special_use(address) (IPv6 transition address)
\* in_network     = the authorized network the address falls in ("" = none)
\* asn_ok         = allowed_asns is empty, or the ASN lookup authorized it
\* country_ok     = allowed_countries is empty, or the country lookup authorized it
Address == [special: BOOLEAN, embedded: BOOLEAN, in_network: STRING,
            asn_ok: BOOLEAN, country_ok: BOOLEAN]

AddressPool ==
    { [special |-> FALSE, embedded |-> FALSE, in_network |-> "",   asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> FALSE, embedded |-> FALSE, in_network |-> "",   asn_ok |-> FALSE, country_ok |-> TRUE],
      [special |-> FALSE, embedded |-> FALSE, in_network |-> "",   asn_ok |-> TRUE,  country_ok |-> FALSE],
      [special |-> TRUE,  embedded |-> FALSE, in_network |-> "",   asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> TRUE,  embedded |-> FALSE, in_network |-> "n1", asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> TRUE,  embedded |-> FALSE, in_network |-> "n2", asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> FALSE, embedded |-> TRUE,  in_network |-> "",   asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> FALSE, embedded |-> TRUE,  in_network |-> "n1", asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> FALSE, embedded |-> FALSE, in_network |-> "n1", asn_ok |-> TRUE,  country_ok |-> TRUE],
      [special |-> TRUE,  embedded |-> FALSE, in_network |-> "n1", asn_ok |-> FALSE, country_ok |-> TRUE] }

\* Resolution results of length 0..MaxAddresses (0 = resolution failure)
AllResolutions ==
    UNION { [1..n -> AddressPool] : n \in 0..MaxAddresses }

ScopeConfig == [include: Seq(STRING), exclude: Seq(STRING),
                authorized_networks: Seq(STRING), allowed_ports: Seq(Int),
                allowed_asns: Seq(Int), allowed_countries: Seq(STRING),
                allow_broad_networks: BOOLEAN, revoked: BOOLEAN,
                expires_at: STRING]

MkScope(inc, exc, nets, ports, asns, countries, broad, revoked, expires) ==
    [include |-> inc, exclude |-> exc, authorized_networks |-> nets,
     allowed_ports |-> ports, allowed_asns |-> asns,
     allowed_countries |-> countries, allow_broad_networks |-> broad,
     revoked |-> revoked, expires_at |-> expires]

\* Legacy public-only policy: the shape most scopes have.
PublicScope == MkScope(<<"*.example">>, <<>>, <<>>, <<>>, <<>>, <<>>, FALSE, FALSE, "none")

Decision == [judged: BOOLEAN, denial: STRING, allowed: BOOLEAN]

Pending == [judged |-> FALSE, denial |-> "", allowed |-> FALSE]

(***************************************************************************)
(* Scopes the model starts requests with                                   *)
(***************************************************************************)

ScopeConfigs ==
    { PublicScope,
      \* default-deny: empty include
      MkScope(<<>>, <<>>, <<>>, <<>>, <<>>, <<>>, FALSE, FALSE, "none"),
      \* excluded host
      MkScope(<<"*.example">>, <<"blocked.example">>, <<>>, <<>>, <<>>, <<>>, FALSE, FALSE, "none"),
      \* port-restricted
      MkScope(<<"*.example">>, <<>>, <<>>, <<80>>, <<>>, <<>>, FALSE, FALSE, "none"),
      \* authorized_networks is an exhaustive allowlist
      MkScope(<<"*.example">>, <<>>, <<"n1">>, <<>>, <<>>, <<>>, FALSE, FALSE, "none"),
      \* networks + ASN + country policy
      MkScope(<<"*.example">>, <<>>, <<"n1">>, <<>>, <<1>>, <<"NP">>, FALSE, FALSE, "none"),
      \* revoked
      MkScope(<<"*.example">>, <<>>, <<"n1">>, <<>>, <<>>, <<>>, FALSE, TRUE, "none"),
      \* expired: expires_at = "past"
      MkScope(<<"*.example">>, <<>>, <<"n1">>, <<>>, <<>>, <<>>, FALSE, FALSE,
              "past") }

\* Parent/child pairs for the inheritance check.
PolicyConfigs ==
    { MkScope(<<"*.example">>, <<>>, <<"n1">>, <<>>, <<>>, <<>>, FALSE, FALSE, "none"),
      MkScope(<<"a.example">>, <<"blocked.example">>, <<"n1">>, <<80, 443>>, <<1, 2>>,
              <<"NP", "US">>, TRUE, FALSE, "future"),
      MkScope(<<"*.example">>, <<"*.example">>, <<"n2">>, <<443>>, <<1>>, <<"NP">>,
              FALSE, FALSE, "past"),
      MkScope(<<"*.example">>, <<>>, <<>>, <<>>, <<>>, <<>>, FALSE, TRUE, "none"),
      MkScope(<<"*.sub.example">>, <<>>, <<"n1">>, <<80>>, <<2>>, <<"US">>, FALSE, FALSE, "none"),
      MkScope(<<"other.example">>, <<>>, <<"n2">>, <<443>>, <<1>>, <<"NP">>, FALSE, FALSE,
              "future") }

(***************************************************************************)
(* Host pattern helpers (mirror _pattern_covers / _listed)                 *)
(***************************************************************************)

EndsWith(str, suffix) ==
    Len(str) >= Len(suffix) /\
    SubSeq(str, Len(str) - Len(suffix) + 1, Len(str)) = suffix

\* Exact host, or "*.domain" matching subdomains (not the bare domain).
Matches(host, pattern) ==
    IF SubSeq(pattern, 1, 2) = "*."
    THEN EndsWith(host, SubSeq(pattern, 2, Len(pattern))) /\
         host # SubSeq(pattern, 3, Len(pattern))
    ELSE host = pattern

PatternCovers(parent, child) ==
    parent = child \/
    (SubSeq(parent, 1, 2) = "*." /\ EndsWith(child, SubSeq(parent, 2, Len(parent))))

IsInternalHost(host) ==
    host = "localhost" \/ \E suffix \in InternalSuffixes: EndsWith(host, suffix)

(***************************************************************************)
(* Sequence helpers - no CHOOSE over a possibly-empty set                  *)
(***************************************************************************)

Elems(seq) == { seq[i] : i \in 1..Len(seq) }

RECURSIVE KeepByMembership(_, _), KeepCovered(_, _), SetToSeq(_), JudgeAll(_, _)

\* Keep the entries of seq that predicate `inkept` accepts.
KeepByMembership(seq, allowed) ==
    IF seq = <<>> THEN <<>>
    ELSE IF Head(seq) \in Elems(allowed)
    THEN <<Head(seq)>> \o KeepByMembership(Tail(seq), allowed)
    ELSE KeepByMembership(Tail(seq), allowed)

\* Keep the entries of childInc that some parent pattern also covers.
KeepCovered(parentInc, childInc) ==
    IF childInc = <<>> THEN <<>>
    ELSE LET p == Head(childInc) IN
         IF \E b \in Elems(parentInc): PatternCovers(b, p)
         THEN <<p>> \o KeepCovered(parentInc, Tail(childInc))
         ELSE KeepCovered(parentInc, Tail(childInc))

\* _intersect_values: an empty list on either side means "any".
IntersectValues(one, other) ==
    IF one = <<>> THEN other
    ELSE IF other = <<>> THEN one
    ELSE KeepByMembership(one, other)

\* _nested_network: the narrower of two networks, "" when unrelated.
NestedNet(child, parent) ==
    IF child = parent THEN child
    ELSE IF Narrows(child, parent) THEN child
    ELSE IF Narrows(parent, child) THEN parent
    ELSE ""

\* _intersect_networks: empty on either side authorizes no internal network.
IntersectNetworks(child, parent) ==
    IF child = <<>> \/ parent = <<>> THEN <<>>
    ELSE LET kept == { NestedNet(c, p) : c \in Elems(child), p \in Elems(parent) } \ {""}
         IN SetToSeq(kept)

\* Finite set -> sequence.  CHOOSE is only reached with S non-empty.
SetToSeq(S) ==
    IF S = {} THEN <<>>
    ELSE LET x == CHOOSE y \in S: TRUE IN
         <<x>> \o SetToSeq(S \ {x})

\* _earlier_expiry: the earliest of the two stamps ("none" = unset).
EarlierTimestamp(one, other) ==
    IF TimestampRank[one] <= TimestampRank[other] THEN one ELSE other

(***************************************************************************)
(* Set views used by the narrowing invariant                               *)
(***************************************************************************)

AllowedPorts(ports) == IF ports = <<>> THEN PortUniverse ELSE Elems(ports)
AllowedAsns(asns) == IF asns = <<>> THEN AsnUniverse ELSE Elems(asns)
AllowedCountries(countries) ==
    IF countries = <<>> THEN CountryUniverse ELSE Elems(countries)

AuthorizedNets(nets) == Elems(nets)

InAnyNetwork(addr, nets) == \E i \in 1..Len(nets): addr.in_network = nets[i]

(***************************************************************************)
(* Inheritance                                                             *)
(***************************************************************************)

InheritResult(parent, child) ==
    [include |-> KeepCovered(parent.include, child.include),
     exclude |-> child.exclude \o parent.exclude,
     authorized_networks |-> IntersectNetworks(child.authorized_networks,
                                               parent.authorized_networks),
     allowed_ports |-> IntersectValues(child.allowed_ports, parent.allowed_ports),
     allowed_asns |-> IntersectValues(child.allowed_asns, parent.allowed_asns),
     allowed_countries |-> IntersectValues(child.allowed_countries,
                                           parent.allowed_countries),
     allow_broad_networks |-> child.allow_broad_networks /\ parent.allow_broad_networks,
     revoked |-> child.revoked \/ parent.revoked,
     expires_at |-> EarlierTimestamp(child.expires_at, parent.expires_at)]

\* Python raises instead of inheriting a list that allows nothing; only
\* feasible pairs produce a successor state.
FeasibleValues(one, other) ==
    one = <<>> \/ other = <<>> \/ Elems(one) \cap Elems(other) # {}

Feasible(parent, child) ==
    KeepCovered(parent.include, child.include) # <<>>
    /\ FeasibleValues(child.allowed_ports, parent.allowed_ports)
    /\ FeasibleValues(child.allowed_asns, parent.allowed_asns)
    /\ FeasibleValues(child.allowed_countries, parent.allowed_countries)

(***************************************************************************)
(* Decision logic (mirror _gate + _judge_addresses + _judge_intel)         *)
(***************************************************************************)

HostGate(scope, host, port) ==
    IF \E i \in 1..Len(scope.exclude): Matches(host, scope.exclude[i])
    THEN "out_of_scope"
    ELSE IF ~(\E i \in 1..Len(scope.include): Matches(host, scope.include[i]))
    THEN "out_of_scope"
    ELSE IF port \notin AllowedPorts(scope.allowed_ports)
    THEN "out_of_scope"
    ELSE ""

\* One address, "" when it passes.  An authorized network is an exhaustive
\* allowlist; with no networks configured only public addresses pass.
AddressVerdict(scope, addr) ==
    IF scope.allowed_asns # <<>> /\ ~addr.asn_ok THEN "policy_unavailable"
    ELSE IF scope.allowed_countries # <<>> /\ ~addr.country_ok THEN "policy_unavailable"
    ELSE IF scope.authorized_networks # <<>>
         THEN (IF InAnyNetwork(addr, scope.authorized_networks) THEN "" ELSE "out_of_scope")
    ELSE IF addr.special \/ addr.embedded THEN "out_of_scope"
    ELSE ""

\* Every address must pass; the first refusal wins.
JudgeAll(scope, addresses) ==
    IF Len(addresses) = 0 THEN ""
    ELSE IF AddressVerdict(scope, addresses[1]) # "" THEN AddressVerdict(scope, addresses[1])
    ELSE JudgeAll(scope, Tail(addresses))

Expired(scope) == scope.expires_at = "past"

Decide(scope, host, port, addresses) ==
    LET gate == HostGate(scope, host, port)
        verdict == JudgeAll(scope, addresses)
    IN IF scope.revoked
       THEN [judged |-> TRUE, denial |-> "revoked", allowed |-> FALSE]
       ELSE IF Expired(scope)
       THEN [judged |-> TRUE, denial |-> "expired", allowed |-> FALSE]
       ELSE IF gate # ""
       THEN [judged |-> TRUE, denial |-> gate, allowed |-> FALSE]
       ELSE IF Len(addresses) = 0
       THEN IF IsInternalHost(host)
            THEN [judged |-> TRUE, denial |-> "out_of_scope", allowed |-> FALSE]
            ELSE [judged |-> TRUE, denial |-> "resolution_failed", allowed |-> FALSE]
       ELSE IF verdict # ""
       THEN [judged |-> TRUE, denial |-> verdict, allowed |-> FALSE]
       ELSE [judged |-> TRUE, denial |-> "", allowed |-> TRUE]

(***************************************************************************)
(* Variables                                                               *)
(***************************************************************************)

VARIABLES
    scope,              \* scope the request is judged against
    host,               \* target host name
    resolution,         \* DNS resolution result (list of addresses)
    decision,           \* verdict for the current (scope, host, resolution)
    validatedIPs,       \* addresses that passed validation
    pinnedIndex,        \* pinned destination: index into validatedIPs, 0 = none
    parentScope,        \* parent policy for inheritance
    childScope,         \* child policy for inheritance
    inheritedScope      \* child narrowed by parent

vars == <<scope, host, resolution, decision, validatedIPs, pinnedIndex,
          parentScope, childScope, inheritedScope>>

(***************************************************************************)
(* Init                                                                    *)
(***************************************************************************)

Init ==
    /\ scope = PublicScope
    /\ host = "a.example"
    /\ resolution = <<>>
    /\ decision = Pending
    /\ validatedIPs = <<>>
    /\ pinnedIndex = 0
    /\ parentScope = PublicScope
    /\ childScope = PublicScope
    /\ inheritedScope = InheritResult(PublicScope, PublicScope)

(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)

\* A new request: pick the scope document and target host.
Configure ==
    /\ scope' \in ScopeConfigs
    /\ host' \in Hosts
    /\ resolution' = <<>>
    /\ decision' = Pending
    /\ validatedIPs' = <<>>
    /\ pinnedIndex' = 0
    /\ UNCHANGED <<parentScope, childScope, inheritedScope>>

\* DNS resolves (or fails) for the current scope.
Resolve ==
    /\ resolution' \in AllResolutions
    /\ decision' = Pending
    /\ validatedIPs' = <<>>
    /\ pinnedIndex' = 0
    /\ UNCHANGED <<scope, host, parentScope, childScope, inheritedScope>>

\* validate_outbound: gate + every address must pass.
Authorize ==
    LET d == Decide(scope, host, TargetPort, resolution)
    IN /\ decision' = d
       /\ validatedIPs' = IF d.allowed THEN resolution ELSE <<>>
       /\ pinnedIndex' = IF d.allowed THEN pinnedIndex ELSE 0
       /\ UNCHANGED <<scope, host, resolution, parentScope, childScope, inheritedScope>>

\* set_pinned_destination: the destination is always one that was validated.
Pin ==
    /\ decision.allowed
    /\ pinnedIndex' \in 1..Len(validatedIPs)
    /\ UNCHANGED <<scope, host, resolution, decision, validatedIPs,
                   parentScope, childScope, inheritedScope>>

\* inherited_from: narrow a child policy by its parent.
InheritScope ==
    /\ parentScope' \in PolicyConfigs
    /\ childScope' \in PolicyConfigs
    /\ Feasible(parentScope', childScope')
    /\ inheritedScope' = InheritResult(parentScope', childScope')
    /\ UNCHANGED <<scope, host, resolution, decision, validatedIPs, pinnedIndex>>

Next ==
    \/ Configure
    \/ Resolve
    \/ Authorize
    \/ Pin
    \/ InheritScope

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* INV1: inherited scope only narrows - every authorization list it hands out
\* is within what both parent and child allowed.
NarrowingInvariant ==
    LET inh == inheritedScope
        child == childScope
        parent == parentScope
    IN /\ inh.include # <<>>
       /\ Elems(inh.include) \subseteq Elems(child.include)
       /\ Elems(child.exclude) \subseteq Elems(inh.exclude)
       /\ Elems(parent.exclude) \subseteq Elems(inh.exclude)
       /\ AllowedPorts(inh.allowed_ports) \subseteq AllowedPorts(child.allowed_ports)
       /\ AllowedPorts(inh.allowed_ports) \subseteq AllowedPorts(parent.allowed_ports)
       /\ AllowedAsns(inh.allowed_asns) \subseteq AllowedAsns(child.allowed_asns)
       /\ AllowedAsns(inh.allowed_asns) \subseteq AllowedAsns(parent.allowed_asns)
       /\ AllowedCountries(inh.allowed_countries) \subseteq AllowedCountries(child.allowed_countries)
       /\ AllowedCountries(inh.allowed_countries) \subseteq AllowedCountries(parent.allowed_countries)
       /\ \A n \in AuthorizedNets(inh.authorized_networks):
              (\E c \in AuthorizedNets(child.authorized_networks): Narrows(n, c)) /\
              (\E p \in AuthorizedNets(parent.authorized_networks): Narrows(n, p))
       /\ (inh.revoked => child.revoked \/ parent.revoked)
       /\ (inh.expires_at # "none" => inh.expires_at \in {child.expires_at, parent.expires_at})
       /\ (inh.allow_broad_networks = (child.allow_broad_networks /\ parent.allow_broad_networks))

\* INV2: a revoked or expired scope never allows.
ExpiryInvariant ==
    decision.judged /\ (scope.revoked \/ Expired(scope))
    => decision.denial \in {"revoked", "expired"}

\* INV3: a pinned destination came from a validated resolution.
PinInvariant ==
    pinnedIndex = 0 \/ pinnedIndex \in 1..Len(validatedIPs)

\* INV4: an empty include is deny-all.
DefaultDenyInvariant ==
    decision.judged /\ scope.include = <<>> => ~decision.allowed

\* INV5: allowing a result means every special-use address it resolved to was
\* inside an explicitly authorized network.
SpecialUseInvariant ==
    decision.judged /\ decision.allowed =>
        \A i \in 1..Len(resolution):
            (resolution[i].special \/ resolution[i].embedded) =>
                InAnyNetwork(resolution[i], scope.authorized_networks)

\* INV6: with authorized_networks configured, a public request whose addresses
\* are all authorized and intel-clean is allowed.
AuthorizedNetworkInvariant ==
    ( decision.judged
    /\ scope.authorized_networks # <<>>
    /\ ~scope.revoked /\ ~Expired(scope)
    /\ HostGate(scope, host, TargetPort) = ""
    /\ Len(resolution) > 0
    /\ \A i \in 1..Len(resolution):
           (InAnyNetwork(resolution[i], scope.authorized_networks)
            /\ resolution[i].asn_ok /\ resolution[i].country_ok) )
    => decision.allowed

(***************************************************************************)
(* Theorems (TLC checks the INVARIANT lines in JudgeAddresses.cfg)         *)
(***************************************************************************)

THEOREM Spec => []NarrowingInvariant
THEOREM Spec => []ExpiryInvariant
THEOREM Spec => []PinInvariant
THEOREM Spec => []DefaultDenyInvariant
THEOREM Spec => []SpecialUseInvariant
THEOREM Spec => []AuthorizedNetworkInvariant

=============================================================================
