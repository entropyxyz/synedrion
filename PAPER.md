Q&A about the CGGN paper https://eprint.iacr.org/2021/060

Replies from Nikos Makriyannis are marked as (NM)


# Notation

- `rid`: (NM) `rid` stands for random identifier, it's supposed to be an unpredictable identifier for the protocol which is chosen via coin-toss.
- `sid` and `ssid`: (NM) The `sid` is the "session identifier" while the `ssid` is the "sub-session identifier". The sid does not change while the ssid changes after each key refresh.
- `[m]` (e.g. in Fig. 17): (NM) `[m]={1,...,m}`.
- `Z_N^*`: (NM) all the invertible elements mod N, so it includes 1.
- In Definition 2.2, the `\rho` argument is the randomizer - it should be freshly sampled each time (and therefore it is omitted as an argument when `enc()` is used later in the protocol)
- Intervals: `I = +- 2^l`, `J = +- 2^l_prime`, `I_eps = +- 2^(l + eps)`, `J_eps = +- 2^(l_prime + eps)` (In Section 3, but seems to be present only in the working copy of the paper)


# Protocol

Q: In Fig. 5 the initial commitment in the Schnorr proof (`A_i`) is sent twice (in R2 and then R3, as a part of `psi_i`), and then the equality of those two values is checked in Output, right before checking the proof itself. But the commitment value is used right after that in the `vrfy` step, so if it doesn't match the rest of the proof, the verification will fail. So is there any security reason for sending the commitment twice? (I understand that it does constitute a minor performance optimization)

A (NM): There is no security reason afaict. You could only send it once.

---

Q: Similarly, the challenge value (`e` in Fig. 2) is sent once with the proof (`psi_i`), and then re-calculated during the `vrfy` step. If we are going to re-calculate it anyway, why include it in `psi_i`? If the re-calculated value is wrong, the proof verification will simply fail.

A (NM): That's correct

---

Q: What is the purpose of the randomness `u` in Fig. 5? It is only used in hashing in R1, but that hash is already randomized by the inclusion of `rid`.

A (NM): The standard way of computing commitments for m with a random oracle H is to calculate H(m,u) for a random u. You could argue that m has enough entropy that you don't need u, but that's your call.

---

Q: In Fig. 3, Key Generation step 2, it says "Run the auxiliary info phase from Fig. 6". That phase takes as input `sid` with some other data, and returns some data that is packed into `ssid`. But in Fig. 6, `ssid` is already present as input, and used throughout the algorithm. Is it a typo?

A (NM): Sorry for the confusion, it's a typo indeed.

---

Q: There is different phrasing used to describe sending messages, e.g. in Figs. 5 and 6:
- "send <...> to all"
- "send <...> to all P_j"
- "broadcast <...>"
Is there any difference between them, or do all of them describe broadcasting, and are only employed for the sake of variety?

A (NM): There is a meaningful difference where "broadcast" indicates that security holds if all parties receive the same message, so the parties need to reach weak consensus about the message  (at the least) e.g via echo broadcasting. On the other hand, for "send to all", the protocol stipulates that the same message is sent to all parties but security is not violated in case a malicious party does not.

---

Q: How do we set `m` in the algorithms from Fig. 16 and 17? Does it depend on the security parameter `kappa`? It does not seem to be listed as a parameter when these algorithms are used (e.g. in Fig. 6).

A (NM): `m` is the statistical security parameter for the proofs in question (which becomes a computational parameter via Fiat Shamir). Using `kappa = m` is fine.

---

Q: Does it matter when selecting `p`, `q` for the Paillier modulus that `p-1` and `q-1` only have small shared divisors (like it is for RSA)?

A (NM): Sampling the Paillier modulus in the same way as an RSA modulus is reasonable (afaict, for random `p` and `q`, `p-1` and `q-1` will not share a large factor).

---

Q: In Fig.6, in the step 1 of Output, there's a special value `\mu` calculated if `x_j^i` does not correspond to `X_j^i`. Is it explained somewhere what that value is, and why the protocol does not just fail?

A (NM): This `\mu` is the randomizer of the ciphertext `C_j^i` i.e. `enc(x_j^i; \mu)=C_j^i`. The purpose of this is for the other parties to re-calculate the encryption and be convinced that `Pj` sent the wrong value (i.e. there is a discrepancy between small `x_j^i` and big `X_j^i` -- the other parties cannot know this without some help from `P_i`).

---

Q: Also, in the calculation of `\mu`, what is `N` without the index? Is it supposed to be `N_j`?

A (NM): It's supposed to be `N_i` (the party that knows the private key for this `N`)


# Layering

Q: In the protocol, messages include sender's ID and `sid` (which, I assume, stands for "session ID"). I wonder if in an implementation it would be a better idea to delegate keeping track of those to the outer "transport" protocol, which will ensure that the given message indeed came from the node it says it was from (e.g. by checking the signature) and only then pass it on to the actual ECDSA logic. Similarly with the session - a node would probably need to be able to participate in several signing rituals simultaneously, so the messages will have to be routed based on `sid`.

A (NM): I'm really not an expert on the implementation side of things, but your suggestion sounds reasonable.
