# UCAN email delegation Spec v0.1.0

[![hackmd-github-sync-badge](https://hackmd.io/V7IxtOYpQqSnWcRuKi6OYg/badge)](https://hackmd.io/V7IxtOYpQqSnWcRuKi6OYg)

## Editors

- [Irakli Gozalishvili](https://github.com/Gozala), [DAG House](https://dag.house/)

## Authors

- [Blaine Cook](https://github.com/blaine), [Fission](https://fission.codes)
- [Irakli Gozalishvili](https://github.com/Gozala), [DAG House](https://dag.house/)

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

# Abstract

As per [core UCAN spec][UCAN spec] implementations MUST support [`did:key`][] method in token's principal identifiers. This specification defines [`did:mailto`][] method for interoperability between implementers that wish to support it in addition to [`did:key`][].


## Motivation

The core [UCAN specification][UCAN spec] defines principals via [`did:key`][] method, which is excellent for cryptographic verifiability, but suboptimal in human context. Specifically [`did:key`][] method identifiers are problematic in below described scenarios:

1. Alice wishes to delegate some capability to Bob. To accomplish this Alice needs to ask Bob for his [`did:key`] and negotiate some side channel through which Bob can send this identifier.

   This is especially suboptimal if both Alice and Bob are in the same phisical space because Bob can not simply pronounce or even remember [`did:key`].
   
2. Service wants to provide familiar email based account recovery flow to their users. To accomplish this service needs to obtain delegation from users principal [`did:key`][] so it could delegate those capabilities back to user during recovery.

   This is especially problematic in web3 context, because same [`did:key`][] could be used across various service providers and delegating all capabilities to one provider would grant it capabilities it otherwise has no access to.

In described scenarios [`did:mailto`] identifiers, provide better tradeoffs in terms of user experience vs security for most users:

1. Alice wishes to delegate some capability to Bob. Chances are high Alice already has Bob's email address unless that is their first acquaintance in which case she can simply ask Bob for his email address.

   Unlike public keys people's email addresses tend to be both pronouncable and memorable so in most cases side channel negotiation could be avoided.
   
2. Service that wants to provide familiar email based recovery flow can facilitate capability delegation from users [`did:key`][] principal to users [`did:mailto`][] and vice versa on recovery.

   This way service will no longer is required to be in the delegation chain.
   
   
## Security Considerations

UCAN issued by a [`did:key`][] principal contains evidence that used identifier is under issuers control, through a token signature _(which can only be produced using private key)_. No such evidence exists when UCAN is issued by a [`did:mailto`][] principal, therefor resolved DID document _(derived from an email message with valid `DKIM-Signature`)_ MUST be provided inside `fct` field.

<!--
It is really annoying that I can't say `fct.dkim` MUST be provided. Furthermore `fct` been array means I could have multilpe `email->key` mappings and it is no longer clear which key to use.

Perhaps it is not too late to consider turning fct to dictionary before 1.0
-->

It is possible to verify that [`did:mailto`][] document was authorized by the owner of that domain _(by verifying that messages `DKIM-Signature` corresponds to the published public key in the DNS)_, from which it could be deduced that issuer is indeed in control of the used email address.

Adversary email provider may exploit putting attacker in control of [`did:mailto`][] identifier and consequently all the capabilities delegated to it.

User could mitigate this by choosing a reputable email provider when delegating capability to [`did:mailto`][].

Attacker that took control of users email could produce UCAN tokens with all of the capabilties that were delegated to it.

Issuers that have delegated capabilities to that email could use UCAN revocation to mitigate it.


## [`did:mailto`] delegate

Implementation adhencing to this specification MUST support delegating to [`did:mailto`][] principal _(UCAN `aud` field)_.

## [`did:mailto`] delegator

Implementation adhencing to this sepecification MUST support delegation from [`did:mailto`][] principal _(UCAN `iss` field)_.

UCAN issuer MUST encode DomainKeys Identified Mail (DKIM) message as an IPLD conforming to [`DomainKeyIdentifiedMail` schema](#DomainKeyIdentifiedMail-Schema) and include an IPLD link to it in `fct` field. Inlining is not supported, but similar effect could be accomplished using a CID with an identity multihash.


Please note that unlike `prf` field, here it MUST be a link as per [DAG-JSON](https://ipld.io/docs/codecs/known/dag-json/), that is `{"/": 'bafy..hash" }` as opposed to string `"bafy..hash"`


## [`did:mailto`] document resolution

UCAN validator MUST obtain `DomainKeyIdentifiedMail` node linked in `fct` and resolve DID document from node's `k` field as per [`did:key`] specification. Resolved document MUST be considered a DID document that issuing [`did:mailto`][] resolves to in only in the context of the enclosed delegation.

Resolved DID document MAY not be used in the rest of this delegation chain or any other delegation. DID document MUST be resolved in each delegation from it's own `fct` field or fail if `fct` is not found.

This resolution allows validator to simply substitute [`did:mailto`] identifier with [`did:key`] and carry on with validation process as per [UCAN core][UCAN spec] specification.


## `DomainKeyIdentifiedMail` Schema

UCAN issuer MUST encode DomainKeys Identified Mail (DKIM) into an IPLD node with following schema, which only contains information allowing validator to:

1. [Resolve `did:mailto` document](#didmailto-document-resolution).
2. Verify that issuer owns [`did:mailto`][] identifier per domain owner authorization.


```ipldsch
type DomainKeysIdentifiedMail {
  -- Public key of the user (MUST be contained by subject)
  userKey PublicKey (rename "i")
  
  -- Domain key of the email
  domainKey PublicKey (rename "k")
  -- integer corresponding to DKIM version
  version DKIMVersion (rename "v" implicit "1")
  -- Hashing algorithm used to hash payload before signing
  hashingAlgorithm Algorithm (rename "a" implicit "0x12")
  -- email username (part before "@" sign)
  user string (rename "u")
  -- Email domain (part after "@""), "d" tag in rfc6376
  domain string (rename "d")
  -- DKIM selector, "s" tag in rfc6376
  selector string (rename "s")
  -- headers that were signed
  headers Headers (rename "h")
  -- Signature, "b" tag in rfc6376
  signature VarSig (rename "b")
}

-- Email headers that were signed represented as
-- listpairs to retain ordering
type Headers {String: String} representation listpairs

-- Public key with a multiformat code tag
type PublicKey bytes

-- Multiformat code corresponding to hashing Algorithm used before signing 
type Algorithm {
  | sha1 ("0x11")
  | sha2_256 ("0x12")
  | sha2_512 ("0x13")
} representation int

-- DKIM Version
type DKIMVersion {
  | One ("1")
} representation string
```




[`did:mailto`]:https://github.com/ucan-wg/did-mailto
[`did:key`]: https://w3c-ccg.github.io/did-method-key/
[UCAN spec]:https://github.com/ucan-wg/spec
[DKIM]:https://www.rfc-editor.org/rfc/rfc6376.html
[rfc6376]:https://www.rfc-editor.org/rfc/rfc6376.html