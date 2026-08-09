# Security policy

CCE is a Python library and command-line tool. It has no hosted service and
no third-party runtime dependencies; `cce-engine serve` binds `127.0.0.1`, requires
the generated bearer token for ordinary requests, and authenticates GitHub
webhooks over their untouched bytes with a separate generated secret. It
still supplies no TLS or OS-user boundary. Everything in scope below is code
in this repository, run locally, against your own data.

The security-relevant surface is the part that decides whether to believe
something: the proof envelope and its verifiers, the completion gate, the
quarantine barrier, the redaction path, and the event and audit chains.

## Supported versions

| Version | Supported |
|---|---|
| Latest commit on `main` | Yes |
| 0.1.x — latest published release | Yes |
| Older releases and arbitrary commits | No |
| Anything else | No such version exists |

This is pre-1.0 software with no release branches. A fix lands on `main`; if it
affects the latest published release, the supported delivery is a new 0.1.x
patch release rather than mutating or backporting to an older artifact.

Hosted CI requires fixes to pass on Python 3.11, 3.12, 3.13 and 3.14 on Linux,
and on Python 3.14 natively on Windows and macOS 15 ARM64.

## Reporting a vulnerability

**Never open a public issue for a security report.** Not for a suspected one
either — if you are unsure whether something is a vulnerability, treat it as
one until it has been triaged.

**Use GitHub private vulnerability reporting: Security tab → Report a
vulnerability.** That is the channel, and reports are welcome. It is the only
one: GitHub has no user-to-user messaging, and the maintainer's GitHub
no-reply address does not accept inbound mail, so a report sent anywhere else
will not arrive.

This project has one maintainer and no on-call rotation. There is no
guaranteed response time and no bug bounty. What is offered instead: a
report that is reproducible will be answered with either a fix or a written
statement of why the behaviour is intended, and the defect will be pinned by
a regression test demonstrated against the recorded pre-fix revision. The
pull-request template requires that evidence; current source alone does not
prove every historical execution.

### What a useful report contains

- The commit SHA you tested.
- A reproduction that runs — a script, a test, a sequence of `cce-engine`
  commands,
  or a crafted envelope plus the verifier invocation that accepts it.
- What you expected the gate, verifier or barrier to do, and what it did.
- Where possible, the attack run against the built artifact rather than
  against the test suite. Two of the worst defects found in this repository
  passed the tests and failed only when driven end to end by hand.

## Known and documented limitations — please do not report these as vulnerabilities

These are design limits, stated in advance in `SPEC.md` §11 and in the
"honest limit" column of `docs/CAPABILITIES.md`. They are not oversights and
a report restating one will be closed with a pointer back here.

1. **Key registry distribution is out of scope.** `SPEC.md` §6 requires an
   out-of-band registry of key fingerprints and says nothing about how it
   travels. CCE ships no channel for it. A stranger still needs the
   fingerprint from somewhere this project does not provide (SPEC.md §11,
   item 3;
   ADR-031, ADR-057).
2. **There is no key revocation mechanism.** A fingerprint in the registry is
   trusted for every envelope it signed. Withdrawing a key is not modelled
   (SPEC.md §11, item 4).
3. **`hmac-sha256` envelopes are not third-party verifiable.** Without the
   secret, an untouched envelope and a resealed forgery are indistinguishable
   to a keyless party, so the verifier returns **UNVERIFIED** — never VALID.
   That verdict is the design working: it means nothing was found wrong and
   nothing was established either, and a caller must not treat it as success.
   Only `lamport-sha256/1` plus an out-of-band fingerprint reaches VALID for a
   stranger (SPEC.md §9, PA-003, ADR-057).
4. **Evidence grading is a mechanical lower bound.** Mutation probes prove a
   check binds to a deliverable's existence and content; they never prove it
   checks the right property. The A–F grade is lint, not an oracle. Whether
   the declared checks test anything worth testing is not decidable from the
   envelope (SPEC.md §11, item 2; EV-007, ADR-027).
5. **Injection screening is pattern-based** and will miss novel phrasing.
   That is why the structural defences — authority typing, quarantine barred
   from every tier and vacating any tier a node already held, the strip at
   the packet exit — do not depend on the patterns catching anything
   (AD-006, ADR-035, ADR-061, ADR-062). The strip's cost is documented
   rather than fixed: text matching cannot distinguish a quarantined payload
   from a live node that quotes it, so an outsider can get a live node
   withheld by quoting it inside content that is then quarantined. Those
   suppressions are named in `omissions` as `quarantined_text_collision` and
   audited — attributable, not prevented (ADR-061). A phrase the screen
   fails to recognise is not a vulnerability; content that reaches control
   state *despite* the structural barriers is (see below).
6. **Rebuildability is bounded by the retention window.** Once SEC-006 clears
   a payload, the projection cannot be rebuilt from the log, and
   `cce-engine rebuild` reports UNDECIDABLE (exit 3) rather than MATCHES or
   DIVERGES. "The log disagrees with the projection" and "the log no longer
   contains what it would take to check" are opposite diagnoses and are
   reported as such (CCG-006, ADR-063).
7. **Freshness is not an envelope property.** Whether the deliverables an
   envelope names still have the digests it records requires the project, not
   the envelope. The engine checks it; a stranger holding only the envelope
   cannot (SPEC.md §11, item 1; ADR-043).
8. **The verifier runner is not a defence against in-process forgery.** A
   test must import the code under test, so the subject can rewrite the
   runner's report. Value-oracle checks and mutation probes exist for that,
   and kernel isolation is deployment work (EV-006, SEC-008, ADR-025).
9. **An anchor published nowhere proves nothing.** The audit chain's
   outermost layer detects tail truncation only if the anchor is published
   somewhere the operator does not control, and CCE ships no publication
   channel (SEC-007, ADR-028).

Two more limits are stated for completeness rather than as report
categories: both implementations of the proof spec have one author, so their
agreement shows the specification is unambiguous enough to reimplement and
not that the implementations are independent (SPEC.md §11, item 5); and tenant
isolation is enforced at application level, not by database row-level security
(SEC-002).

## What is a vulnerability

Defeating a structural defence is a vulnerability, and it is exactly what
this project wants reported. Concretely:

- **Forging a proof that passes the completion gate.** An envelope that
  `verifiers/verify_proof.py` reports VALID, or that `complete_task` accepts,
  when it should not be. Any bypass of one of the completion gate's
  independent rejection checks counts, including a proof whose required
  verifiers did not actually run (EV-004, ADR-019, ADR-024).
- **Spending one proof on two tasks** — or across projects or tenants, or
  binding a proof to a task through an unsigned field. Completion by replay
  is the failure ADR-018 exists to prevent.
- **Getting quarantined text into a resume packet**, into any memory tier,
  or into retrieval output, by any route. Untrusted text becoming control
  state is the failure AD-006 exists to prevent, and the barrier is supposed
  to hold at the exit regardless of what the screen recognised.
- **Escaping an autonomy downgrade**, for instance by relabelling an action
  so the policy no longer applies to it.
- **Tampering with the event or audit chain** without `cce-engine audit verify`
  reporting it, within the anchor limitation stated above.
- **A verifier or evidence-probe sandbox escape** — anything that writes,
  reads or executes outside the sandbox the probe is supposed to be confined
  to, or that damages the real working tree.
- **Secrets surviving redaction** into persisted state, or reaching the graph
  after a capture mode said they would not (SEC-003, ADR-016).
- **A conformance divergence** where `causal_continuity_engine/proof.py`,
  `verifiers/verify_proof.py`
  and `SPEC.md` do not agree — one accepting what another rejects. The
  `vectors/` corpus is the arbiter, not either implementation's opinion.
- **Anything that makes a false completion look like a true one**, whether or
  not it fits a category above. That is the property the trust layer exists
  to hold: absence of success is never success.

## Coordinated disclosure

Report through the private-vulnerability-reporting channel above and give a
fix a reasonable window before publishing. If a
report is valid, the advisory will credit you by whatever name and link you
ask for, or anonymously if you prefer. If a report is not valid, you will get
the reasoning rather than silence.
