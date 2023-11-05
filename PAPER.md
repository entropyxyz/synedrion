Q&A about the CGGN paper https://eprint.iacr.org/2021/060

Replies from Nikos Makriyannis are marked as (NM)


# Notation

- `rid`: (NM) `rid` stands for random identifier, it's supposed to be an unpredictable identifier for the protocol which is chosen via coin-toss.
- `sid` and `ssid`: (NM) The `sid` is the "session identifier" while the `ssid` is the "sub-session identifier". The sid does not change while the ssid changes after each key refresh.
- `[m]` (e.g. in Fig. 17): (NM) `[m]={1,...,m}`.
- `Z_N^*`: (NM) all the invertible elements mod N, so it includes 1.
- In Definition 2.2, the `\rho` argument is the randomizer - it should be freshly sampled each time (and therefore it is omitted as an argument when `enc()` is used later in the protocol)
- Intervals: `I = +- 2^l`, `J = +- 2^l_prime`, `I_eps = +- 2^(l + eps)`, `J_eps = +- 2^(l_prime + eps)` (In Section 3, but seems to be present only in the working copy of the paper)
- The subscript `j` in `П^enc`, `П^log` etc (e.g. in Fig. 7) indicates which party's Pedersen parameters -- the tuple `(\hat{N}, s, t)` -- should be used when generating the proof.


# Typos

The randomness derivation (`\mu` in Output, step 1, in Fig. 6) is overly complicated - `\mu = (C mod N)^(N^(-1) mod phi(N))` works just as well. Also, `(1 + N)^m mod N^2 == (1 + m * N) mod N^2`, which is much faster to compute, but I guess the exponential form is conventional.

In `П^{fac}` (Fig. 28), step 2: `q` the curve order, not to be confused with `q` the RSA prime in the Inputs.

In `П^{aff-g}` (Fig. 15) I had to modify the proof to account for how `D` is actually constructed in the Presigning protocol. In the proof it is assumed that `D = C (*) x (+) enc(y)` (where `(*)` and `(+)` are homomorphic operations on Paillier ciphertexts), but in the Presigning it's actually `D = C (*) x (+) enc(-y)` (see Fig. 7, Round 2, step 2). So I had to modify the following:
- (prover) `T = s^{-y} t^\mu \mod \hat{N}`
- (prover) `z_2 = \beta - e y`
- (prover) `\omega_y = r_y \rho_y^{-e} \mod N_1`
- (verifier checks) `enc_1(z_2, \omega_y) = B_y (+) Y (*) (-e)`

In `П^{mul*}`, Fig. 30:
- the prover creates `B_x`, but sends `B` - a typo, and they're the same thing;
- the prover creates `r_y`, but it is unused - a typo;
- `\beta` used to create `A` is not mentioned anywhere else (and judging by the condition the verifier checks, it should be equal to zero) - should be ignored (set to 0).

In Presigning (Fig. 7), Round 2, step 2 `r_{i,j}` and `\hat{r}_{i,j}` should be drawn from `\mathbb{Z}_{N_i}`, and not `N_j`, judging by how they are used later.


# Protocol

Q: `\ell`, `ell_prime`, `\eps`, and corresponding intervals (\mathcal{I} and \mathcal{J}, see e.g. Fig. 7) - what are they equal to? It is mentioned that they will be "determined by the analysis", but I could not find the values specified. I found one mention of the range parameters (and the security parameter `m`): the caption of Table 2 in Appendix D. It gives `m = 80`, `\ell = \kappa`, `\ell^\prime = 5 \kappa`, `\eps = 2 \kappa`, where `\kappa` is the bit length of the curve order, so 256 for secp256k1. Also Fig. 28 in Section C.5 fixes the size of the RSA modulus as `log2(N) = 4 \ell + 2 \eps` (which gives 2048 bit). I'm currently using these as production parameters, but it seems weird that they're hidden in such obscure places.

A (NM): Those are the recommended values.

---

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

---

Q: During the KeyRefresh/Auxiliary protocol each node generates ring-Pedersen parameters `s` and `t`. I looked through Presigning and all the proofs used there, and they don't seem to be used anywhere. One possibility is that these are actually the setup parameters for the proofs, but then it's strange that the paper doesn't mention generating the corresponding public Paillier key `\hat{N}`. I guess, a possibility is that the Paillier key each node generates *is* the auxiliary setup for ZK proofs. That would certainly make things faster since we would only have to generate one Paillier key instead of two, and that is the slowest part of key refresh.

A (NM): Using the same value for `N` and `\hat{N}` does not affect security as far as we can tell.

---

Q: According to according to "Generating the Setup Parameter for the Range Proofs" in Section 2.3, the setup parameters `(\hat{N}, s, t)` used in several ZK proofs (`fac`, `enc`, `aff-g`, `log*` etc) are generated once by each node separately and then sent to other nodes along with `П^{prm}` and `П^{mod}`. This is not present explicitly in any protocols, so my current theory is that each node generates them once in KeyRefresh/Auxiliary protocol, along with the main Paillier key, and then other nodes use it later in KeyRefresh/Auxiliary and Presigning when creating the proofs. Is that correct?

A (NM): The setup parameters should be chosen afresh with each key-refresh.

---

Q: How does the range limitation in `П^{fac}` (Fig. 28) work? Specifically, how does the range check on `z_1` and `z_2` guarantee `p, q > 2^\ell`? I suppose there's a probabilistic guarantee that `p, q < 2^\eps \sqrt{N_0}`, which, along with the condition `p q = N_0` gives `p, q > 2^\eps` (but then the range check for `z_1` and `z_2` should perhaps be at `\sqrt{N_0} * 2^{\ell + \eps + 1}`).

A (NM): The parties check that `z1,z2 < \pm \sqrt{N0}*2^{\ell+\eps}` which means that `p, q < \pm \sqrt{N0}*2^{\ell+\eps}`. Since `N0` is a biprime (and it only has two factors), it follows that `p,q > 2^\ell` because `N0 \approx 2^{\ell} * \sqrt{N0}*2^{\ell+\eps}`.

---

Q: Speaking of the `p, q > 2^\ell` guarantee in `П^{fac}`: isn't it quite weak, given the value of `\ell` in the production parameters? If one factor of an RSA modulus is 256 bit, it is possible to decompose it in a reasonable time.

A (NM): We want N0 not to have small factors in order for the ZK proofs elsewhere to be sound (it's not related to the hardness of factoring the modulus).

---

Q: What should I take as `\sqrt{N_0}` in `П^{fac}` (Fig. 28)? Lower bound (2^1023), upper bound (2^1024), faithful square root?

A (NM): Either one should be fine.


# Layering

Q: In the protocol, messages include sender's ID and `sid` (which, I assume, stands for "session ID"). I wonder if in an implementation it would be a better idea to delegate keeping track of those to the outer "transport" protocol, which will ensure that the given message indeed came from the node it says it was from (e.g. by checking the signature) and only then pass it on to the actual ECDSA logic. Similarly with the session - a node would probably need to be able to participate in several signing rituals simultaneously, so the messages will have to be routed based on `sid`.

A (NM): I'm really not an expert on the implementation side of things, but your suggestion sounds reasonable.
