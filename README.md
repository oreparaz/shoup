# shoup: multi-party RSA signing

shoup is a prototype implementation of Shoup's threshold RSA [1].
Shoup gave an efficient procedure to compute RSA signatures
without needing to store or hold secret key material in a
single place (not even during computation).

The magic dust is _multi-party computation_. Loosely speaking, in this
setting several parties cooperate to compute a private operation
(in this case, RSA signing). Each party holds only a share of the
private key and can't learn anything about others' secrets.
Plenty of asterisks apply here, but the general idea is that even if
some subset of parties get corrupted, by construction the protocol
guarantees that (unshared) secrets don't leak.

Shoup's multi-party RSA signing is remarkable for its simplicity
and very manageable overhead. You can realistically do RSA-4096
with tens of parties with regular hardware. For precise definitions
of security goals that the protocol achieves, refer to Shoup's paper [1].

In this implementation, arithmetic is provided by sage and
prime generation is offloaded to OpenSSL.

**⚠️ Warning: unaudited code with zero review**

### PSS padding

It's possible to extend this to use a proper padding scheme, such as PSS.
The padding operation is public; thus we just have to make sure nobody
fiddles with randomness. This can be as easy as

 1. each party broadcasts a commitment for a random 128-bit seed
 1. each party discloses the 128-bit seed, and verifies that everyone's commitments were sound
 1. hash everyone's 128-bit seed, use the (public) result to crank a PRNG and use the PRNG output in PSS padding

I've a working prototype but needs a bit more work.

### Contact

Oscar Reparaz <firstname.lastname@esat.kuleuven.be>

### References

[1] V. Shoup, _Practical Threshold Signatures_, Eurocrypt 2000. https://www.shoup.net/papers/thsig.pdf
