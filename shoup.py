#!/usr/bin/env python

# A prototype implementation of threshold RSA, following
# V. Shoup, "Practical Threshold Signatures", Eurocrypt 2000
# https://www.shoup.net/papers/thsig.pdf (Algorithm 1)
#
# run as /path/to/sage -python shoup.py
#
# Warning: unaudited code.
#
# Copyright (c) 2019 Oscar Reparaz <firstname.lastname@esat.kuleuven.be>


from sage.all import *
import random
import hashlib


# An identifier for this current version of the script.
# Note that all parties must run the same version;
# different versions are *not* interoperable on purpose.
__version__ = '2019-12-01/001'

urandom = random.SystemRandom()


def random(n):
    return urandom.randint(0, n-1)  # inclusive 0 and n-1


def pow_mod(base, exponent, modulo):
    return power_mod(int(base), int(exponent), modulo)


def mul_mod(op1, op2, modulo):
    return mod(int(op1) * int(op2), modulo)


def is_sophie_germain(n):
    return is_prime(n) and is_prime((n-1)/2)


def openssl_generate_safe_prime(bits):
    # shell out to openssl for safe prime generation
    import subprocess
    cmd = "openssl prime -bits %d -checks 128 -generate -safe" % bits
    ret = int(subprocess.check_output(cmd.split(' ')))
    assert(is_sophie_germain(ret))
    assert(ret.bit_length() == bits)
    return Integer(ret)


def prime_gen(param):
    L = param['rsa_modulus_length_in_bits']
    p = openssl_generate_safe_prime(L / 2)
    q = openssl_generate_safe_prime(L / 2)
    while p == q:  # can happen w/ short primes (e.g., testing)
        # very small L can make this loop non-terminating
        q = openssl_generate_safe_prime(L / 2)
    return (p, q)


def primes_from_file(param):
    from Crypto.PublicKey import RSA  # unmaintained
    f = open('test/sk.pem', 'rb')
    key = RSA.importKey(f.read())
    # key = RSA.generate(2048)
    f.close()
    return (Integer(key.p), Integer(key.q))


def key_gen(param, primes):
    (p, q) = primes

    m = ((p-1)/2) * ((q-1)/2)

    # Shoup's protocol requires the RSA public exponent e be larger
    # than the number parties. Hence, the value e = 2**16 + 1 (F4)
    # should satisfy all reasonable needs. Hardcode it here.
    e = 0x10001
    assert(e > param['number_parties_total'])

    sk_unshared = {
        'p': p,
        'q': q,
        'd': pow_mod(e, -1, m),
        'm': m,
    }
    pk = {
        'n': p * q,
        'e': e,
    }
    return (sk_unshared, pk)


def export_key(sk, pk):
    # Export *unshared* private key and public key to PEM file
    from Crypto.PublicKey.RSA import construct  # unmaintained
    pubkey = construct((int(pk['n']), int(pk['e'])))
    privkey = construct((int(pk['n']), int(pk['e']), int(sk['d']),
                         int(sk['p']), int(sk['q'])))
    print("RSA public key:")
    print(pubkey.exportKey())
    print("RSA unshared private key: ")
    print(privkey.exportKey(format="PEM", pkcs=8))

    # inspect with
    #   openssl rsa -inform PEM -in sk.pem -text -noout
    #   openssl rsa -inform PEM -pubin -in pk.pem -text -noout


def evaluate_poly(poly, point, m):
    ret = 0
    for i in range(len(poly)):
        ret = ret + mod((poly[i] * mod(point ** i, m)), m)
    return mod(ret, m)


def split_shamir(secret, number_coeffs, number_shares, modulus):
    a = [0] * number_coeffs
    a[0] = secret

    for i in range(1, number_coeffs):
        a[i] = random(modulus)
    s = [0] * number_shares
    for i in range(number_shares):
        s[i] = evaluate_poly(a, i+1, modulus)
        # sweis adds here a random multiple of m
        # https://github.com/sweis/threshsig/blob/master/src/main/java/threshsig/Dealer.java#L165
    return s


def deal(param, sk_unshared, pk):
    # Generate shares for the secret key by Shamir splitting
    # and shares of the verification key.
    n = pk['n']

    s = split_shamir(secret=sk_unshared['d'],
                     number_coeffs=param['number_parties_needed'],
                     number_shares=param['number_parties_total'],
                     modulus=sk_unshared['m'])

    # verification keys
    v_pre = random(n)
    assert(gcd(v_pre, n) == 1)
    v = mul_mod(v_pre, v_pre, n)

    vs = [0] * param['number_parties_total']
    for i in range(len(vs)):
        vs[i] = pow_mod(v, s[i], n)

    sk_shared = {
        'v': v,
        's': s,
        'vs': vs,
    }
    return sk_shared


def signature_shares(param, pk, sk_shared, message):
    xi = [0] * param['number_parties_total']
    for i in range(param['number_parties_total']):
        exponent = 2 * param['delta'] * sk_shared['s'][i]
        xi[i] = pow_mod(message, exponent, pk['n'])
    return xi


def lagrange(S, i, j, delta):
    ret = delta
    for j_prime in S:
        if j_prime != j:
            ret = (ret * (i - j_prime)) / (j - j_prime)
    return ret


def reconstruct_signature_shares(param, pk, sigshares, message):
    n = pk['n']
    e = pk['e']
    delta = param['delta']
    e_prime = 4 * delta * delta
    (gcd_e_eprime, bezout_a, bezout_b) = xgcd(e_prime, e)
    assert(gcd_e_eprime == 1)

    w = 1
    quorum = list(range(1, param['number_parties_needed']+1))
    for i in quorum:
        exponent = 2 * lagrange(quorum, 0, i, delta)
        part = pow_mod(sigshares[i-1], exponent, n)
        w = mul_mod(w, part, n)

    assert(pow_mod(w, e, n) == pow_mod(message, e_prime, n))

    p1 = pow_mod(w, bezout_a, n)
    p2 = pow_mod(message, bezout_b, n)
    signature_recombined = mul_mod(p1, p2, n)

    assert(pow_mod(signature_recombined, e, n) == message)
    return signature_recombined


def hash_transcript(**transcript):
    hexdigest = hashlib.sha256(str(transcript)).hexdigest()
    return int(hexdigest, base=16)


def lift_message(message, delta, n):
    return pow_mod(message, 4*delta, n)


def construct_proofs(param, pk, sk_shared, message, sigshares):
    n = pk['n']
    v = sk_shared['v']
    L = param['number_parties_total']
    xt = lift_message(message, param['delta'], n)
    proofs = [0] * L
    quorum = list(range(L))
    for i in quorum:
        r = random(n)
        c = hash_transcript(script_version=__version__,
                            param=param,
                            pk=pk,
                            party_index=i,
                            v=v,
                            xt=xt,
                            vi=sk_shared['vs'][i],
                            xi2=pow_mod(sigshares[i], 2, n),
                            vp=pow_mod(v, r, n),
                            xp=pow_mod(xt, r, n))
        z = int(sk_shared['s'][i])*c + r
        proofs[i] = (z, c)

    return proofs


def verify_proofs(param, pk, sk_shared, proofs, message, sigshares):
    n = pk['n']
    v = sk_shared['v']
    xt = lift_message(message, param['delta'], n)
    quorum = list(range(param['number_parties_total']))
    for i in quorum:
        their_z, their_c = proofs[i]

        vp1 = pow_mod(v, their_z, n)
        vp2 = pow_mod(sk_shared['vs'][i], -their_c, n)

        xp1 = pow_mod(xt, their_z, n)
        xp2 = pow_mod(sigshares[i], -2*their_c, n)

        our_c = hash_transcript(script_version=__version__,
                                param=param,
                                pk=pk,
                                party_index=i,
                                v=v,
                                xt=xt,
                                vi=sk_shared['vs'][i],
                                xi2=pow_mod(sigshares[i], 2, n),
                                vp=mul_mod(vp1, vp2, n),
                                xp=mul_mod(xp1, xp2, n))
        assert(our_c == their_c)


param = {
    # RSA modulus length, in bits.
    # A toy value suitable for testing is, e.g., 100.
    # A more realistic value is, e.g., 3072
    'rsa_modulus_length_in_bits': 3072,
    # Number of signature shares needed to obtain a signature.
    # This is k in the paper.
    'number_parties_needed': 3,
    # Number of players engaging in the protocol. This is l in the paper.
    'number_parties_total': 4,
    # This is t in the paper. max k-1. Currently unused in this code.
    'number_parties_corrupted': 1,
}


def validate_param(param):
    assert(param['number_parties_needed'] >=
           param['number_parties_corrupted']+1)
    assert((param['number_parties_total'] - param['number_parties_corrupted'])
           >= param['number_parties_needed'])
    param['delta'] = factorial(param['number_parties_total'])


def test_shamir():
    # Test Shamir shares do not leak more than necessary.
    #
    # In a (n, k) secret sharing, any k-1 shares should be
    # independent of the secret. Here, k=2, which means
    # one piece is independent from the secret, but two
    # disclose it.
    #
    m = 7  # work in the small field F_7 (small field -> bias easier to detect)
    number_shares = 3  # number of pieces
    number_coeffs = 2  # poly of order 1
    number_samples = 10000
    for picked_shares in range(1, number_shares+1):
        c0s = []
        c1s = []
        for i in range(number_samples):
            # shares for secret 0
            s0 = split_shamir(0, number_coeffs, number_shares, m)
            # shares for secret 2
            s1 = split_shamir(2, number_coeffs, number_shares, m)
            c0 = 1
            c1 = 1
            for j in range(picked_shares):
                c0 = c0 * s0[j]
                c1 = c1 * s1[j]
            c0s.append(float(c0))
            c1s.append(float(c1))

        expected_leak = False
        if picked_shares >= number_coeffs:
            expected_leak = True
        welch_num = (mean(c0s) - mean(c1s))
        welch_den = sqrt((variance(c0s)/len(c0s)) + (variance(c1s)/len(c1s)))
        welch = welch_num / welch_den
        leak = abs(welch) > 5
        assert(leak == expected_leak)


def setup(param, pem_file=None):
    validate_param(param)
    if pem_file:
        (sk_unshared, pk) = key_gen(param, primes_from_file(param))
    else:
        (sk_unshared, pk) = key_gen(param, prime_gen(param))
    # export_key(sk_unshared, pk)
    sk_shared = deal(param, sk_unshared, pk)
    return (sk_shared, pk)


def random_message(pk):
    return random(pk['n'])


def round1(param, pk, sk_shared, message_to_sign):
    sigshares = signature_shares(param, pk, sk_shared, message_to_sign)
    proofs = construct_proofs(param, pk, sk_shared,
                              message_to_sign, sigshares)
    return (sigshares, proofs)


def round2(param, pk, sk_shared, message_to_sign, sigshares, proofs):
    verify_proofs(param, pk, sk_shared, proofs, message_to_sign, sigshares)
    signature_recombined = reconstruct_signature_shares(param,
                                                        pk,
                                                        sigshares,
                                                        message_to_sign)
    return signature_recombined


def test_roundtrip():
    (sk_shared, pk) = setup(param)
    message_to_sign = random_message(pk)
    (sigshares, proofs) = round1(param, pk, sk_shared, message_to_sign)
    round2(param, pk, sk_shared, message_to_sign, sigshares, proofs)


def test_cheat():
    (sk_shared, pk) = setup(param)
    message_to_sign = random_message(pk)
    (sigshares, proofs) = round1(param, pk, sk_shared, message_to_sign)
    proofs[0] = (proofs[0][0], proofs[0][1]+1)  # cheat
    detected_corruption = False
    try:
        round2(param, pk, sk_shared, message_to_sign, sigshares, proofs)
    except AssertionError:
        detected_corruption = True
    assert(detected_corruption)


while True:
    test_shamir()
    test_roundtrip()
    test_cheat()
    print("OK")
