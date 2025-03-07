Q&A about the CGGN paper https://eprint.iacr.org/2021/060 (the figure and section numbers refer to the 2024-10-21 revision)

Replies from Nikos Makriyannis are marked as (NM)


# Notation

- `[m]` (e.g. in Fig. 17): (NM) `[m]={1,...,m}`.
- `Z_N^*`: (NM) all the invertible elements mod N, so it includes 1.
- In Definition 3.2, the `\rho` argument is the randomizer - it should be freshly sampled each time (and therefore it is omitted as an argument when `enc()` is used later in the protocol)
- Intervals: `I = ±2^l`, `J = ±2^l_prime`, `I_eps = ±2^(l + eps)`, `J_eps = ±2^(l_prime + eps)` (See Nota Bene just before Section 4.1)
- The subscript `j` in `П^{enc-elg}`, `П^log` etc (e.g. in Fig. 8) indicates which party's Pedersen parameters -- the tuple `(\hat{N}, s, t)` -- should be used when generating the proof.
- Not notation from the paper per se, but used throughout the code: `(+)` and `(*)` stand for the homomorphic addition of Paillier ciphertexts and the homomorphic multiplication of a ciphertext and a plaintext. That is, `A (+) B == A B mod N^2` and `A (*) x == A^x mod N^2`, where `N` is the Paillier modulus.


# Typos

In `П^{dec}` (Fig. 28), Inputs, the condition `(1 + N)^z` should read `(1 + N)^y`. Also note that at the point where it is used, the first secret argument corresponds to `y`, and the second to `x`.

Also in `П^{dec}`: In Fig. 8 and 9, and in Section 4.3.1, where `П^{dec}` is used it is given a fifth public parameter, not mentioned in Fig. 28. It seems that Fig. 28 takes it to be `g` (curve generator), which is the case in Figs. 8 and 9, but in Section 4.3.1 it is given the point `\Gamma` instead.

In `П^{aff-g}` (Fig. 25) I had to modify the proof to account for how `D` is actually constructed in the Presigning protocol. In the proof it is assumed that `D = C (*) x (+) enc(y)` (where `(*)` and `(+)` are homomorphic operations on Paillier ciphertexts), but in the Presigning it's actually `D = C (*) x (+) enc(-y)` (see Fig. 8, Round 2, step 2). So I had to modify the following:
- (prover) `T = s^{-y} t^\mu \mod \hat{N}`
- (prover) `z_2 = \beta - e y`
- (prover) `w_y = r_y \rho_y^{-e} \mod N_1`
- (verifier checks) `enc_1(z_2, w_y) = B_y (+) Y (*) (-e)`

Same applies to `П^{aff-g*}` (Fig. 27).

In `П^{enc-elg}` (Fig. 24) the secret parameter `a` is not actually used in the proof - it is an ephemeral secret.

In Presigning (Fig. 8), Round 2, step 2 `r_{i,j}` and `\hat{r}_{i,j}` should be drawn from `\mathbb{Z}_{N_i}`, and not `N_j`, judging by how they are used later.

Fig. 7 (KeyRefresh): there is a variable `B` that is not introduced anywhere, but used in hashes - must be forgotten from the previous revision.

Fig. 7 (KeyRefresh): `srid` is not introduced anywhere - probably should be `rid`.

Fig. 7 (KeyRefresh), Output, 1. (c): should be `\hat{\psi}_{j,k}`, not `\psi_{j,k}`. `\psi_{j,k}` are `П^{fac}`, not `П^{sch}`.

Fig. 8 (Presigning): the order of public parameters for `П^{elog}` is different from the one in Fig. 23. For example, in Round 2, 2a), the order is `\Gamma_i, g, B_{i,1}, B_{i,2}, Y_i`, but it should be `B_{i,1}, B_{i,2}, Y_i, \Gamma_i, g`.

Fig. 9, Output potentially needs `D_{k,j}` for all `k, j` (`k != j`) to calculate `D_j`. But, with the messages described in Fig. 8, a party `i` would only have `D_{j,i}`, `j!=i` (the ones it created in Round 2), and `D_{i,j}`, `j!=i` (the ones it received from other nodes). How are we supposed to obtain the rest? One option is to echo-broadcast (echo, so that they could be used to generate a verifiable evidence, too) all `D_{j,i}` and `F_{j,i}` in Round 2 instead of sending each `D_{j,i}` and `F_{j,i}` to the corresponding node `j`. Same goes for `\hat{D}` and `\hat{F}`.

The above item leads to another problem. If those values are indeed echo-broadcasted, what malicious actions of one node can lead to passing the `П^{dec}` check on other nodes, but failing one of the `П^{aff-g*}` ones?

Fig. 8, Round 2, 2b) - `\psi_{j,i}` creation requires `F_{i,j}` which are not yet available since they're the ones created on other nodes. The previous paper version has `F_{j,i}` there. Same for `\hat{\psi_{j,i}}`.


# Echo-broadcasting

In order to be able to generate verifiable evidence for each failure, some values have to be echo-broadcasted instead of normal broadcast/direct messaging given in the paper. Here is the list of such variables

KeyInit (Fig. 6):
- `rho_i` in Round 2

KeyRefresh (Fig. 7):
- `rid_i`, `\hat{N}_i`, `s_i`, `t_i`, `\vec{Y}` in Round 2

Presigning (Fig. 8):
- `\Gamma_i`, `F_{j,i}` for all `j`, `\hat{F}_{j,i}` for all `j` in Round 2
- `\delta_i` in Round 3


# Protocol

Q: In Fig. 6 the initial commitment in the Schnorr proof (`A_i`) is sent twice (in R2 and then R3, as a part of `psi_i`), and then the equality of those two values is checked in Output, right before checking the proof itself. But the commitment value is used right after that in the `vrfy` step, so if it doesn't match the rest of the proof, the verification will fail. So is there any security reason for sending the commitment twice? (I understand that it does constitute a minor performance optimization)

A (NM): There is no security reason afaict. You could only send it once.

---

Q: Similarly, the challenge value (`e` in Fig. 3) is sent once with the proof (`psi_i`), and then re-calculated during the `vrfy` step. If we are going to re-calculate it anyway, why include it in `psi_i`? If the re-calculated value is wrong, the proof verification will simply fail.

A (NM): That's correct

---

Q: What is the purpose of the randomness `u` in Fig. 6? It is only used in hashing in R1, but that hash is already randomized by the inclusion of `rid`.

A (NM): The standard way of computing commitments for m with a random oracle H is to calculate H(m,u) for a random u. You could argue that m has enough entropy that you don't need u, but that's your call.

---

Q: There is different phrasing used to describe sending messages, e.g. in Figs. 6 and 7:
- "send <...> to all"
- "send <...> to all P_j"
- "broadcast <...>"
Is there any difference between them, or do all of them describe broadcasting, and are only employed for the sake of variety?

A (NM): There is a meaningful difference where "broadcast" indicates that security holds if all parties receive the same message, so the parties need to reach weak consensus about the message  (at the least) e.g via echo broadcasting. On the other hand, for "send to all", the protocol stipulates that the same message is sent to all parties but security is not violated in case a malicious party does not.

---

Q: How do we set `m` in the algorithms from Fig. 12 and 13? Does it depend on the security parameter `kappa`? It does not seem to be listed as a parameter when these algorithms are used (e.g. in Fig. 6).

A (NM): `m` is the statistical security parameter for the proofs in question (which becomes a computational parameter via Fiat Shamir). Using `kappa = m` is fine.

---

Q: Does it matter when selecting `p`, `q` for the Paillier modulus that `p-1` and `q-1` only have small shared divisors (like it is for RSA)?

A (NM): Sampling the Paillier modulus in the same way as an RSA modulus is reasonable (afaict, for random `p` and `q`, `p-1` and `q-1` will not share a large factor).

---

Q: How does the range limitation in `П^{fac}` (Fig. 26) work? Specifically, how does the range check on `z_1` and `z_2` guarantee `p, q > 2^\ell`? I suppose there's a probabilistic guarantee that `p, q < 2^\eps \sqrt{N_0}`, which, along with the condition `p q = N_0` gives `p, q > 2^\eps` (but then the range check for `z_1` and `z_2` should perhaps be at `\sqrt{N_0} * 2^{\ell + \eps + 1}`).

A (NM): The parties check that `z1,z2 < ±\sqrt{N0}*2^{\ell+\eps}` which means that `p, q < ±\sqrt{N0}*2^{\ell+\eps}`. Since `N0` is a biprime (and it only has two factors), it follows that `p,q > 2^\ell` because `N0 \approx 2^{\ell} * \sqrt{N0}*2^{\ell+\eps}`.

---

Q: Speaking of the `p, q > 2^\ell` guarantee in `П^{fac}`: isn't it quite weak, given the value of `\ell` in the production parameters? If one factor of an RSA modulus is 256 bit, it is possible to decompose it in a reasonable time.

A (NM): We want N0 not to have small factors in order for the ZK proofs elsewhere to be sound (it's not related to the hardness of factoring the modulus).

---

Q: What should I take as `\sqrt{N_0}` in `П^{fac}` (Fig. 26)? Lower bound (2^1023), upper bound (2^1024), faithful square root?

A (NM): Either one should be fine.


# Layering

Q: In the protocol, messages include sender's ID and `sid` (which, I assume, stands for "session ID"). I wonder if in an implementation it would be a better idea to delegate keeping track of those to the outer "transport" protocol, which will ensure that the given message indeed came from the node it says it was from (e.g. by checking the signature) and only then pass it on to the actual ECDSA logic. Similarly with the session - a node would probably need to be able to participate in several signing rituals simultaneously, so the messages will have to be routed based on `sid`.

A (NM): I'm really not an expert on the implementation side of things, but your suggestion sounds reasonable.
