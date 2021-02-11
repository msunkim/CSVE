/* ****************************************************************************************************************************************************************** *\
 * @file    csve.h                                                                                                                                                    *
 * @author  Myungsun Kim                                                                                                                                              *
 * @date    Feb. 10, 2021                                                                                                                                             *
 * @brief   Camenisch-Shoup verifiable encryption                                                                                                                     *
 *                                                                                                                                                                    *
\* ****************************************************************************************************************************************************************** */

#ifndef __CAMENISCH_SHOUP_VE_H
#define __CAMENISCH_SHOUP_VE_H

#include <iostream>
#include <string>
#include <chrono>
#include <fstream>
#include <sstream>

#include <cstddef>
#include <cassert>

#include <openssl/sha.h>

#include <NTL/ZZ.h>

using namespace NTL;

namespace _CS {
const uint32_t  OPENSSL_HASH_BYTES = 32;
const uint32_t  ell = 1024;
const ZZ        one(1);
const ZZ        zero(0);

/**
 * @brief key structures
 * 
 */
struct _public_key {
    ZZ  _n,
        _n_prime,
        _n_sqr;
    ZZ  _zeta;      //< zeta = (1 + n) mod n^2    
    ZZ  _g;
    ZZ  _y_1, 
        _y_2, 
        _y_3;
    ZZ  _g_tilde,   //< order = n'
        _h_tilde;
};

struct _secret_key {
    ZZ  x_1_, 
        x_2_, 
        x_3_;
};

/**
 * @brief Camenisch-Shoup ciphertext
 * 
 */
struct _ciphertext {
    ZZ  _u, 
        _e,
        _v;
};

/**
 * @brief   encryption proof
 * 
 */
struct _proof {
    ZZ      _delta,                     //< random bases
            _gamma,
            _y_hat;                     
    ZZ      _v_tilde,                   //< commitments
            _u_prime,
            _e_prime,
            _v_prime,
            _delta_prime,
            _v_tilde_prime;             
    uint8_t _c[OPENSSL_HASH_BYTES];    //< challenge
    ZZ      _r_bar,
            _m_bar,
            _s_bar;                     //< responses
};

void _random_oracle(uint8_t challenge[OPENSSL_HASH_BYTES], const std::string& input);
void _setup(ZZ& n, ZZ& n_sqr, ZZ& n_prime, ZZ& zeta);
void _key_generation(_public_key& pk, _secret_key& sk);
void _prove_encryption(const _public_key pk, const ZZ y_hat, const ZZ r, const ZZ m, _proof& pf);
void _encrypt(const _public_key pk, const ZZ m, _ciphertext& c, _proof& pf);
void _decrypt(const _public_key pk,  const _secret_key sk, const _ciphertext& c, ZZ& p);
bool _verify_encryption(const _public_key pk, const _ciphertext cpx, const _proof pf);
}

#endif //__CAMENISCH_SHOUP_VE_H