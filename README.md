# custody

**Threshold custody for sealed secrets: `m` of `n` custodians must agree
before anything opens — and a check that the `m` actually means something.**

Pure `.cljc`, no runtime dependencies. Runs identically on the JVM and under
nbb (both suites are the same files: 22 tests / 83 assertions).

```clojure
(require '[custody.shamir :as shamir] '[custody.model :as custody])

;; 3-of-5, one share per custodian, custodians in different domains
(def shares (shamir/split recovery-key 3 5 secure-random-bytes))

(def deal
  (custody/deal "deal:itonami/recovery/2026-07"
    {:secret-id     "envelope:drv:abc123#recovery"
     :threshold     3
     :total         5
     :secret-digest (sha256-b64 recovery-key)
     :custodians    [{:custodian/id "did:key:z6Mk…" :custodian/domain :tenant   :custodian/pub "…"}
                     {:custodian/id "did:key:z6Mk…" :custodian/domain :tenant   :custodian/pub "…"}
                     {:custodian/id "did:key:z6Mk…" :custodian/domain :operator :custodian/pub "…"}
                     {:custodian/id "did:key:z6Mk…" :custodian/domain :notary   :custodian/pub "…"}
                     {:custodian/id "did:key:z6Mk…" :custodian/domain :counsel  :custodian/pub "…"}]}))

(custody/independence deal)
;=> {:independence/min-domains-to-open 2
;    :independence/captured-by         nil
;    :independence/can-deny            #{:tenant}
;    :independence/sound?              true}

(custody/open deal releases sha256-b64)
;=> {:custody/opened? true :custody/secret […]}
```

## Why `independence` is the point

Splitting a secret 3-of-5 is arithmetic, and the arithmetic is easy. The part
that is easy to get wrong — and impossible for the algebra to notice — is
**who holds the shares**. Three of five shares sitting in one operator's
control is a 1-of-1 wearing a costume. `custody.model/independence` is the
check that says so:

- `:independence/captured-by` — the domain that can open the secret alone.
  Non-nil means the threshold is decorative.
- `:independence/min-domains-to-open` — the fewest distinct parties that can
  reach the threshold together. `1` is the same failure stated as a number.
- `:independence/can-deny` — domains that can make recovery *impossible* by
  refusing. Reported, but deliberately **not** part of `sound?`: a tenant that
  can block its own recovery is usually the intent; an operator that can is a
  hostage situation, and this library will not guess which one you meant.

`:independence/sound?` is the invariant worth gating a deployment on.

## What it does not do

- **No crypto primitives.** `shamir/split` takes a `rand-bytes-fn`;
  `model/open` takes a `digest-fn`. A portable namespace cannot honestly
  claim a secure RNG on every runtime this workspace targets, and one that
  quietly fell back to `rand-int` would be worse than one with no opinion.
  Share wrapping to each custodian's X25519 public key is
  [`kotoba-lang/envelope`](https://github.com/kotoba-lang/envelope)'s job;
  this library only names the AAD that wrap must bind (`model/share-aad`).
- **It does not hide the secret's length.** Every share is exactly as long as
  the secret. Pad first if that matters.
- **Shamir alone cannot tell you the quorum was wrong.** Combine the wrong
  shares and you get a different secret, not an error — there is no redundancy
  in the algebra to notice with. That is what `:deal/secret-digest` is for,
  and why `shamir/combine` is deliberately the *unverified* primitive while
  `model/open` is the one you should call. The test
  `a-wrong-quorum-returns-a-plausible-secret-instead-of-an-error` pins the
  behaviour so it is documented by a passing assertion rather than discovered
  during a recovery.
- **Rotation is not an epoch bump.** `model/rotate` returns a *shell* with the
  custodians and digest cleared, because re-splitting and re-wrapping is the
  only thing that actually retires old shares. Bumping the epoch stops old
  shares from being accepted; it does not make a custodian who already
  unwrapped one forget it — the same honesty `envelope.model/revoke` applies
  to a deleted wrap.

## Structural refusals

`model/quorum-error` reports disagreement before insufficiency, so a caller
collecting shares sees the real problem as soon as it appears:

| reason | what it caught |
|---|---|
| `:foreign-deal` / `:foreign-secret` | a share for something else |
| `:mixed-epoch` | a share from a retired generation being replayed |
| `:unknown-share-x` | a coordinate belonging to no custodian |
| `:custodian-share-mismatch` | a custodian presenting someone else's coordinate |
| `:share-x-disagreement` | the release and the share inside it disagree |
| `:duplicate-share` | the same custodian counted twice |
| `:below-threshold` | not enough, checked last |

## Lineage

Replaces the `kotoba-custody` Rust crate cited by ADR-2607061900, removed with
the rest of the Rust tree (ADR-2607072000). The `GrantedShare` shape that ADR
described — epoch, deal binding, per-requester re-wrap — is what `share-aad`
and `quorum-error` reconstruct in `.cljc`. Consumed by the cloud-itonami
sealed plane (ADR-2607285000).

```bash
clojure -M:test                              # JVM
nbb --classpath "src:test" scripts/run-tests.cljs   # ClojureScript
```

AGPL-3.0-or-later.
