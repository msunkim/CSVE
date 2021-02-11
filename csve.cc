/* ****************************************************************************************************************************************************************** *\
 * @file    csve.cc                                                                                                                                                   *
 * @author  Myungsun Kim                                                                                                                                              *
 * @date    Feb. 10, 2021                                                                                                                                             *
 * @brief   Camenisch-Shoup verifiable encryption                                                                                                                     *
 *                                                                                                                                                                    *
\* ****************************************************************************************************************************************************************** */

#include "csve.h"

using namespace NTL;

namespace _CS {
/**
 * @brief random oracle
 * 
 */
void 
_random_oracle(uint8_t challenge[OPENSSL_HASH_BYTES], const std::string& input)
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.data(), input.size());
	SHA256_Final(challenge, &ctx);

    return;
}

/**
 * @brief setup
 * 
 */
void 
_setup(ZZ& n, ZZ& n_sqr, ZZ& n_prime, ZZ& zeta)
{
    ZZ p, q;

    //< safe primes
    GenGermainPrime(p, ell);
    GenGermainPrime(q, ell);

    //< the RSA modulus
    n = p * q;
    n_prime = ((p - 1 ) / 2) * ((q - 1) / 2);
    n_sqr = n * n;
    
    //< a default generator
    //< zeta = (1 + n) mod n^2
    zeta = AddMod(one, n, n_sqr);

    return;
}

/**
 * @brief key generation
 * 
 */
void
_key_generation(_public_key& pk, _secret_key& sk)
{
    ZZ g_prime;
#ifdef _DEBUG
    std::cout << "pk._n_sqr = " << pk._n_sqr << std::endl;
    std::cout << "pk._n = " << pk._n << std::endl;
#endif

    //< choose randoms
    RandomBits(sk.x_1_, 2 * ell - 2);
    RandomBits(sk.x_2_, 2 * ell - 2);
    RandomBits(sk.x_3_, 2 * ell - 2);
#ifdef _DEBUG
    std::cout << "sk.x_1_ = " << sk.x_1_ << std::endl;
    std::cout << "sk.x_2_ = " << sk.x_2_ << std::endl;
    std::cout << "sk.x_3_ = " << sk.x_3_ << std::endl;
#endif

    //< other key values
    while (true) {
        RandomLen(g_prime, 2 * ell - 2);
        ZZ d = GCD(g_prime, pk._n_sqr);
        if (1 == d) {
            break;
        }
    }
#ifdef _DEBUG
    std::cout << "g_prime = " << g_prime << std::endl;
#endif    
    pk._g = PowerMod(g_prime, 2 * pk._n, pk._n_sqr);
    pk._y_1 = PowerMod(pk._g, sk.x_1_, pk._n_sqr);
    pk._y_2 = PowerMod(pk._g, sk.x_2_, pk._n_sqr);
    pk._y_3 = PowerMod(pk._g, sk.x_3_, pk._n_sqr);

    //< parameters for proofs
    while (true) {
        RandomBits(pk._g_tilde, 2 * ell - 2);
        ZZ a = PowerMod(pk._g_tilde, pk._n_prime, pk._n);
        if (1 == a) {
            break;
        }
    }

    while (true) {
        RandomBits(pk._h_tilde, 2 * ell - 2);
        ZZ a = PowerMod(pk._h_tilde, pk._n_prime, pk._n);
        if (1 == a) {
            break;
        }
    }

    return;
}

/**
 * @brief generate a proof of correct encryption
 * 
 */
void
_prove_encryption(const _public_key pk, const ZZ y_hat, const ZZ r, const ZZ m, _proof& pf)
{
    ZZ          c, s, t, r_prime, m_prime, s_prime, twor_prime;
    size_t      vlen = 0, dlen = 0;
    uint8_t*    vstr = 0;
    uint8_t*    dstr = 0;
    std::string input;

    //< randomizers
    RandomBits(s, ell);
    RandomBits(r_prime, ell);
    twor_prime = 2 * r_prime;
    RandomBits(m_prime, ell);
    RandomBits(s_prime, ell);

    //< random bases
    RandomBits(t, ell);
    pf._gamma = PowerMod(pk._zeta, t, pk._n_sqr);
    pf._y_hat = y_hat;

    //< \delta = \gamma^m
    pf._delta = PowerMod(pf._gamma, m, pk._n_sqr);

    //< \tilde{v} = \tilde{g}^m\tilde{h}^s
    pf._v_tilde = PowerMod(pk._g_tilde, m, pk._n_sqr);
    t = PowerMod(pk._h_tilde, s, pk._n_sqr);
    pf._v_tilde = MulMod(pf._v_tilde, t, pk._n_sqr);

    //< \prime{u} = g^{2\prime{r}}
    pf._u_prime = PowerMod(pk._g, twor_prime, pk._n_sqr);

    //< \prime{e} = y_1^{2\prime{r}}\zeta^{2\prime{m}}
    pf._e_prime = PowerMod(pk._y_1, twor_prime, pk._n_sqr);
    t = PowerMod(pk._zeta, 2 * m_prime, pk._n_sqr);
    pf._e_prime = MulMod(pf._e_prime, t, pk._n_sqr);

    //< \prime{v} = \hat{y}^{2\prime{r}}
    pf._v_prime = PowerMod(y_hat, twor_prime, pk._n_sqr);

    //< \prime{\delta} = \gamma^{\prime{m}}
    pf._delta_prime = PowerMod(pf._gamma, m_prime, pk._n_sqr);

    //< \tilde{\prime{v}} = \tilde{g}^{\prime{m}}\tilde{h}^{\prime{s}}
    pf._v_tilde_prime = PowerMod(pk._g_tilde, m_prime, pk._n_sqr);
    t = PowerMod(pk._h_tilde, s_prime, pk._n_sqr);
    pf._v_tilde_prime = MulMod(pf._v_tilde_prime, t, pk._n_sqr);

    //< random oracle
    //< for simplicity, use \tilde{v} and \delta; however, in practice use all commitments
    vlen = NumBytes(pf._v_tilde);
    dlen = NumBytes(pf._delta);

    vstr = new uint8_t[vlen];
    std::memset(vstr, 0, sizeof(uint8_t) * vlen);
    dstr = new uint8_t[dlen];
    std::memset(dstr, 0, sizeof(uint8_t) * dlen);

    BytesFromZZ(vstr, pf._v_tilde, vlen);
    BytesFromZZ(dstr, pf._delta, dlen);

    input.append(reinterpret_cast<const char*>(vstr), vlen);
    input.append(reinterpret_cast<const char*>(dstr), dlen);

    _random_oracle(pf._c, input);
    c = ZZFromBytes(pf._c, OPENSSL_HASH_BYTES);

    //< responses
    pf._r_bar = r_prime - c * r;    //< in ZZ
    pf._m_bar = m_prime - c * m;
    pf._s_bar = s_prime - c * s;

    delete[] vstr; vstr = 0;
    delete[] dstr; dstr = 0;

    return;
}

/**
 * @brief encryption
 * 
 */
void
_encrypt(const _public_key pk, const ZZ m, _ciphertext& c, _proof& pf)
{
    size_t      ulen = 0, elen = 0;
    uint8_t*    ustr = 0;
    uint8_t*    estr = 0;
    ZZ          r, y_hat, h, f;
    uint8_t*    hash = 0;
    std::string input;

    //< randomizer
    RandomBits(r, 2 * ell - 2);

    //< encrypting
    c._u = PowerMod(pk._g, r, pk._n_sqr);
    c._e = PowerMod(pk._y_1, r, pk._n_sqr);
    f = PowerMod(pk._zeta, m, pk._n_sqr);
    c._e = MulMod(c._e, f, pk._n_sqr);

    ulen = NumBytes(c._u);
    elen = NumBytes(c._e);
    ustr = new uint8_t[ulen];
    std::memset(ustr, 0, sizeof(uint8_t) * ulen);
    estr = new uint8_t[elen];
    std::memset(estr, 0, sizeof(uint8_t) * elen);
    BytesFromZZ(ustr, c._u, ulen);
    BytesFromZZ(estr, c._e, elen);
    input.append(reinterpret_cast<const char*>(ustr), ulen);
    input.append(reinterpret_cast<const char*>(estr), elen);

    hash = new uint8_t[OPENSSL_HASH_BYTES];
    std::memset(hash, 0, sizeof(uint8_t) * OPENSSL_HASH_BYTES);

    _random_oracle(hash, input);
#ifdef _DEBUG
    for(auto i = 0; i < OPENSSL_HASH_BYTES; i++) {
        std::printf("%02x", hash[i]);
    }
    std::printf("\n");
#endif
    h = ZZFromBytes(hash, OPENSSL_HASH_BYTES);
    y_hat = PowerMod(pk._y_3, h, pk._n_sqr);
    y_hat = MulMod(pk._y_2, y_hat, pk._n_sqr);
    c._v = PowerMod(y_hat, r, pk._n_sqr);

    delete[] ustr; ustr = 0;
    delete[] estr; estr = 0;
    delete[] hash; hash = 0;

    //< proof generation
    _prove_encryption(pk, y_hat, r, m, pf);

    return;
}



/**
 * @brief decryption
 * 
 */
void
_decrypt(const _public_key pk,  const _secret_key sk, const _ciphertext& c, ZZ& p)
{
    size_t      ulen = 0, elen = 0;
    ZZ          h, l, r, e, f;
    uint8_t*    ustr = 0;
    uint8_t*    estr = 0;
    uint8_t*    hash = 0;
    std::string input;

    ulen = NumBytes(c._u);
    elen = NumBytes(c._e);
    ustr = new uint8_t[ulen];
    std::memset(ustr, 0, sizeof(uint8_t) * ulen);
    estr = new uint8_t[elen];
    std::memset(estr, 0, sizeof(uint8_t) * elen);
    BytesFromZZ(ustr, c._u, ulen);
    BytesFromZZ(estr, c._e, elen);
    input.append(reinterpret_cast<const char*>(ustr), ulen);
    input.append(reinterpret_cast<const char*>(estr), elen);

    hash = new uint8_t[OPENSSL_HASH_BYTES];
    std::memset(hash, 0, sizeof(uint8_t) * OPENSSL_HASH_BYTES);

    _random_oracle(hash, input);
#ifdef _DEBUG
    for(auto i = 0; i < OPENSSL_HASH_BYTES; i++) {
        std::printf("%02x", hash[i]);
    }
    std::printf("\n");
#endif
    h = ZZFromBytes(hash, OPENSSL_HASH_BYTES);

    //< check if u^{2(x_2+H(u,e,L)*x_3)} == v^2
    e = 2 * (sk.x_2_ + h * sk.x_3_);
    l = PowerMod(c._u, e, pk._n_sqr);
    r = MulMod(c._v, c._v, pk._n_sqr);
    assert (r == l);

    //< recover the message
    // n_inv = InvMod(pk._n, pk._n_sqr);
    f = InvMod(c._u, pk._n_sqr);
    f = PowerMod(f, sk.x_1_, pk._n_sqr);
    f = MulMod(c._e, f, pk._n_sqr);
    f = f - 1;
    div(p, f, pk._n);

    delete[] ustr; ustr = 0;
    delete[] estr; estr = 0;
    delete[] hash; hash = 0;

    return;
}

/**
 * @brief verify if an encryption is correct
 * 
 */
bool 
_verify_encryption(const _public_key pk, const _ciphertext cpx, const _proof pf)
{
    ZZ          l, r, t, c;
    ZZ          two_c, two_bar_r;
    std::string input;
    uint8_t*    hash = 0;
    uint8_t*    vstr = 0;
    uint8_t*    dstr = 0;
    size_t      vlen = 0, dlen = 0;
    
    //< challenge
    vlen = NumBytes(pf._v_tilde);
    dlen = NumBytes(pf._delta);

    vstr = new uint8_t[vlen];
    std::memset(vstr, 0, sizeof(uint8_t) * vlen);
    dstr = new uint8_t[dlen];
    std::memset(dstr, 0, sizeof(uint8_t) * dlen);

    BytesFromZZ(vstr, pf._v_tilde, vlen);
    BytesFromZZ(dstr, pf._delta, dlen);

    input.append(reinterpret_cast<const char*>(vstr), vlen);
    input.append(reinterpret_cast<const char*>(dstr), dlen);

    hash = new uint8_t[OPENSSL_HASH_BYTES];
    std::memset(hash, 0, sizeof(uint8_t) * OPENSSL_HASH_BYTES);

    _random_oracle(hash, input);
    assert(0 == std::memcmp(hash, pf._c, OPENSSL_HASH_BYTES));
    c = ZZFromBytes(hash, OPENSSL_HASH_BYTES);

    //< \prime{u} = u^{2c}g^{2\bar{r}}
    two_c = 2 * c;
    two_bar_r = 2 * pf._r_bar;

    l = PowerMod(cpx._u, two_c, pk._n_sqr);
    r = PowerMod(pk._g, two_bar_r, pk._n_sqr);
    t = MulMod(l, r, pk._n_sqr);
    assert(t == pf._u_prime);

    //< \prime{e} = e^{2c}y_1^{2\bar{r}}\zeta^{2\bar{m}}
    l = PowerMod(cpx._e, two_c, pk._n_sqr);
    r = PowerMod(pk._y_1, two_bar_r, pk._n_sqr);
    t = PowerMod(pk._zeta, 2 * pf._m_bar, pk._n_sqr);
    t = MulMod(t, r, pk._n_sqr);
    t = MulMod(t, l, pk._n_sqr);
    assert(t == pf._e_prime);

    //< \prime{v} = v^{2c}\hat{y}^{2\bar{r}}
    l = PowerMod(cpx._v, two_c, pk._n_sqr);
    r = PowerMod(pf._y_hat, two_bar_r, pk._n_sqr);
    t = MulMod(l, r, pk._n_sqr);
    assert(t == pf._v_prime);

    //< \prime{\delta} = \delta^c\gamma^{\bar{m}}
    l = PowerMod(pf._delta, c, pk._n_sqr);
    r = PowerMod(pf._gamma, pf._m_bar, pk._n_sqr);
    t = MulMod(l, r, pk._n_sqr);
    assert(t == pf._delta_prime);

    //< \bar{\tilde{v}} = \tilde{v}^c\tilde{g}^{\bar{m}}\tilde{h}^{\bar{s}}
    l = PowerMod(pf._v_tilde, c, pk._n_sqr);
    r = PowerMod(pk._g_tilde, pf._m_bar, pk._n_sqr);
    t = PowerMod(pk._h_tilde, pf._s_bar, pk._n_sqr);
    t = MulMod(t, r, pk._n_sqr);
    t = MulMod(t, l, pk._n_sqr);
    assert(t == pf._v_tilde_prime);

    delete[] hash; hash = 0;
    delete[] vstr; vstr = 0;
    delete[] dstr; dstr = 0;

    return true;
}
}
