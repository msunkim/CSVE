A Camenisch-Shoup Verifiable Encryption Implementation
================================================================================

--------------------------------------------------------------------------------
Authors and contacts
--------------------------------------------------------------------------------

The implementation is developed by [Myungsun Kim](http://msuny.net) and is released under the MIT License (see the [LICENSE] file).

--------------------------------------------------------------------------------
[TOC]

<!---
  NOTE: the file you are reading is in Markdown format, which is fairly readable
  directly, but can be converted into an HTML file with much nicer formatting.
  To do so, run "make doc" (this requires the python-markdown package) and view
  the resulting file README.html. Alternatively, view the latest HTML version at
  https://github.com/scipr-lab/libsnark .
-->

--------------------------------------------------------------------------------
Overview
--------------------------------------------------------------------------------

This package implements __Camenisch-Shoup__ Verifiable Encryption scheme \[CS03], which is a cryptographic primitive for supporting a setting where there are two parties who are in a position to prove some property to another party about an encrypted message and the party who holds the secret key.
A protocol in which the encryptor is the prover is a verifiable encryption protocol, while a protocol in which the decryptor is the prover is a verifiable decryption protocol. This implementation only focuses on the former case, namely, _verifiable encryption_.

In particular, this implementation realizes a verifiable encryption introduced by Camenisch and Shoup \[CS03] at Crypto 2003. This work clearly has a better performance than some other works such as \[ASW98], \[Sta96], and \[YY98].


This code is a C++ implementation together with NTL 11.4.3 and openssl (LibeSSL 2.8.3) and includes a simple test code. For simplicity I provide a Makefile rather than using cmake.

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

### Dependencies

The libsnark library relies on the following:

- C++ build environment
- MakeFile
- [NTL](https://libntl.org) library for group operations in the same setting as the Paillier cryptosystem
- [openssl](https://www.openssl.org/source/) for simulating a random oracle


So far I have tested these only on Machintosh, specifically iMac 3.7 GHz 6 cores Intel i5 with 32GB RAM, though I believe this implementation has little portability issues because NTL and openssl can be well installed on Linux and Windows via Cygwin.


### Building

After cloning this code from their GitHub repos, then, to build the implementation and run the binary:

    $ make
    $ ./csve

### Remarks

This code originally developed to estimate the running times during encrypting a plaintext along with generating a proof of a correct encryption and verifing the corresponding proof, in the [IITP](https://www.iitp.kr/main.it) project: __(2018-0-00251, Privacy-Preserving and Vulnerability Analysis for Smart Contract)__. However, for completeness this code implements the decryption algorithm *without verifiable decryption property*. If necessary, you may remove the run-time estimation modules.


--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

\[CS03] [_Practical Verifiable Encryption and Decryption of Discrete Logarithms_](https://eprint.iacr.org/2002/161), Jan Camenisch and Victor Shoup, Crypto 2003

\[ASW98] [_Optimistic Fair Exchange of Digital Signatures_](https://eprint.iacr.org/1997/015),   N. Asokan, Victor Shoup and Michael Waidner, Eurocrypt 1998

\[Sta96] [_Publicly Verifiable Secret Sharing_](https://www.ubilab.org/publications/print_versions/pdf/sta96.pdf),   Markus Stadler,  Eurocrypt 1996

\[YY98] [  _Auto-Recoverable Auto-Certifiable Cryptosystems_](https://www.iacr.org/cryptodb/data/paper.php?pubkey=2882),   Adam L. Young and Moti Yung, Eurocrypt 1998

[LICENSE]: LICENSE (LICENSE file in root directory of the implementation)
