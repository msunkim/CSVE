/* ****************************************************************************************************************************************************************** *\
 * @file    test.cc                                                                                                                                                   *
 * @author  Myungsun Kim                                                                                                                                              *
 * @date    Feb. 10, 2021                                                                                                                                             *
 * @brief   main                                                                                                                                                      *
 *                                                                                                                                                                    *
\* ****************************************************************************************************************************************************************** */
#include <iostream>

#include "csve.h"

using namespace NTL;

/**
 * @brief main
 * 
 */
int 
main(int argc, char** argv)
{
    ZZ                  n, n_sqr, n_prime, zeta;
    _CS::_public_key    pk;
    _CS::_secret_key    sk;
    std::ofstream       prover_time, verifier_time;
	std::stringstream   ptime, vtime;
    const uint32_t      rep = 100;

    //< system parameters
    _CS::_setup(n, n_sqr, n_prime, zeta);
    
    //< key generation
    pk._n = n;
    pk._n_prime = n_prime;
    pk._n_sqr = n_sqr;
    pk._zeta = zeta;
    _CS::_key_generation(pk, sk);

#ifdef _DEBUG
    std::cout << "pk._n_sqr = " << pk._n_sqr << std::endl;
    std::cout << "pk._n = " << pk._n << std::endl;
    std::cout << "pk._g = " << pk._g << std::endl;
    std::cout << "pk._y_1 = " << pk._y_1 << std::endl;
    std::cout << "pk._y_2 = " << pk._y_2 << std::endl;
    std::cout << "pk._y_3 = " << pk._y_3 << std::endl;
    std::cout << "pk._zeta = " << pk._zeta << std::endl;
#endif    

    //< encryption
    ZZ               m, p;
    _CS::_ciphertext c;
    _CS::_proof      pf;        //< proof of encryption
    bool             accept = false;
    double_t         ptotal = 0.0, vtotal = 0.0;

    for (auto i = 0; i < rep; i++) {
        RandomBits(m, _CS::ell);

        auto begin_prover = std::chrono::high_resolution_clock::now();
        _CS::_encrypt(pk, m, c, pf);
        auto end_prover = std::chrono::high_resolution_clock::now();
    	auto elapsed_prover = std::chrono::duration_cast<std::chrono::nanoseconds>(end_prover - begin_prover);

        //< proving time check
        prover_time.open("prover_time.txt", std::ofstream::out | std::ofstream::app);
		ptime << (i+1) << "-th prover run-time = " << elapsed_prover.count() * 1e-6 << " msec" << std::endl;
		prover_time << ptime.str();
		prover_time.close();

        ptotal = ptotal + elapsed_prover.count() * 1e-6;
#ifdef _DEBUG
        std::cout << "m = " << m << std::endl;
#endif

        auto begin_verifier = std::chrono::high_resolution_clock::now();
        accept = _CS::_verify_encryption(pk, c, pf);
        assert(true == accept);

        //< verfication time check
        auto end_verifier = std::chrono::high_resolution_clock::now();
    	auto elapsed_verifier = std::chrono::duration_cast<std::chrono::nanoseconds>(end_verifier - begin_verifier);

		///< write
		verifier_time.open("verifier_time.txt", std::ofstream::out | std::ofstream::app);
		vtime << (i+1) << "-th verifier run-time = " << elapsed_verifier.count() * 1e-6 << " msec" << std::endl;
		verifier_time << vtime.str();
		verifier_time.close();

        vtotal = vtotal + elapsed_verifier.count() * 1e-6;

        //< decryption
        _CS::_decrypt(pk, sk, c, p);
        if (m != p) {
            std::cout << "decryption failed!!" << std::endl;
            return -1;
        }
        std::cout << (i+1) << "-th decryption is ok!" << std::endl;
#ifdef _DEBUG
        std::cout << "p = " << p << std::endl;
#endif
    }

#ifdef __DEBUG
    std::printf("The avg prover time   = %f\n", ptotal / rep);
    std::printf("The avg verifier time = %f\n", vtotal / rep);  
#endif

    return 1;
}