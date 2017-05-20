//
// Copyright (c) 2014, Ruben De Visscher
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
#pragma once

#include <iostream>
extern "C" {
#include <sodium.h>
}

namespace sodiumpp {
    std::string crypto_auth(const std::string &m,const std::string &k);
    void crypto_auth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_box(const std::string &m,const std::string &n,const std::string &pk,const std::string &sk);
    std::string crypto_box_keypair(std::string *sk_string);
    std::string crypto_box_beforenm(const std::string &pk, const std::string &sk);
    std::string crypto_box_afternm(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_box_open(const std::string &c,const std::string &n,const std::string &pk,const std::string &sk);
    std::string crypto_box_open_afternm(const std::string &c,const std::string &n,const std::string &k);
    std::string crypto_hash(const std::string &m);
    std::string crypto_onetimeauth(const std::string &m,const std::string &k);
    void crypto_onetimeauth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_scalarmult_base(const std::string &n);
    std::string crypto_scalarmult(const std::string &n,const std::string &p);
    std::string crypto_secretbox(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_secretbox_open(const std::string &c,const std::string &n,const std::string &k);
    std::string crypto_sign_keypair(std::string *sk_string);
    std::string crypto_sign_open(const std::string &sm_string, const std::string &pk_string);
    std::string crypto_sign(const std::string &m_string, const std::string &sk_string);
    std::string crypto_stream(size_t clen,const std::string &n,const std::string &k);
    std::string crypto_stream_xor(const std::string &m,const std::string &n,const std::string &k);

    std::string bin2hex(const std::string& bytes);
    void memzero(std::string& bytes);

    // ============================================================================================
    // public_key
    // ============================================================================================

    class public_key
    {
    private:
        std::string bytes_;
        public_key() {}
        friend class secret_key;

    public:
        public_key(const std::string& bytes) : bytes_(bytes) {}
        std::string get() const { return bytes_; }
    };
    std::ostream& operator<<(std::ostream& stream, const public_key& pk);

    // ============================================================================================
    // secret_key
    // ============================================================================================

    class secret_key
    {
    private:
        std::string secret_bytes_;

    public:
        public_key pk;
        secret_key(const public_key& pk_, const std::string& secret_bytes)
            : secret_bytes_(secret_bytes)
            , pk(pk_)
        {}
        secret_key() {
            pk.bytes_ = crypto_box_keypair(&secret_bytes_);
        }
        std::string get() const { return secret_bytes_; }
        ~secret_key() {
            memzero(secret_bytes_);
        }
    };
    std::ostream& operator<<(std::ostream& stream, const secret_key& sk);

    // ============================================================================================
    // nonce
    // ============================================================================================

    template <unsigned int constantbytes, unsigned int sequentialbytes>
    class nonce
    {
    private:
        std::string bytes;
        bool overflow;

    public:
        static_assert(constantbytes < crypto_box_NONCEBYTES and sequentialbytes <= crypto_box_NONCEBYTES and constantbytes + sequentialbytes == crypto_box_NONCEBYTES, "constantbytes + sequentialbytes needs to be equal to crypto_box_NONCEBYTES and sequentialbytes needs to be greater than 0");

        nonce()
            : bytes("")
            , overflow(false)
        {}

        // @param constant Constant part of the nonce.
        // @param uneven Flag marking odd side of nonce sequential generation.
        //
        //     Distinct messages between the same {sender, receiver} set are required
        //     to have distinct nonces. For example, the lexicographically smaller
        //     public key can use nonce 1 for its first message to the other key,
        //     nonce 3 for its second message, nonce 5 for its third message, etc.,
        //     while the lexicographically larger public key uses nonce 2 for its
        //     first message to the other key, nonce 4 for its second message,
        //     nonce 6 for its third message, etc. Nonces are long enough that
        //     randomly generated nonces have negligible risk of collision.
        //
        nonce(const std::string& constant, bool uneven)
            : bytes(constant)
            , overflow(false)
        {
            if (constant.size() > 0 and constant.size() != constantbytes) {
                throw "constant bytes do not have correct length";
            }
            bytes.resize(crypto_box_NONCEBYTES, 0);
            if (constant.size() == 0) {
                randombytes_buf(&bytes[0], constantbytes);
            }
            if (uneven) {
                bytes[bytes.size()-1] = 1;
            }
        }
        std::string next()
        {
            unsigned int carry = 2;
            for (size_t i = bytes.size()-1; i >= constantbytes and carry > 0; --i)
            {
                unsigned int current = *reinterpret_cast<unsigned char *>(&bytes[i]);
                current += carry;
                *reinterpret_cast<unsigned char *>(&bytes[i]) = current & 0xff;
                carry = current >> 8;
            }
            if (carry > 0) {
                overflow = true;
            }
            return get();
        }
        std::string get() const
        {
            if (overflow) {
                throw "overflow in sequential part of nonce";
            } else {
                return bytes;
            }
        }
        std::string constant() const { return bytes.substr(0, constantbytes); }
        std::string sequential() const { return bytes.substr(constantbytes, sequentialbytes); }
    };

    template <unsigned int constantbytes, unsigned int sequentialbytes>
    std::ostream& operator<<(std::ostream& s, nonce<constantbytes, sequentialbytes> n)
    {
        s << bin2hex(n.constant()) << "-" << bin2hex(n.sequential());
        return s;
    }

    // ============================================================================================
    // source_nonce
    // Class wrapping a received nonce for unboxing
    // ============================================================================================

    template <unsigned int constantbytes>
    class source_nonce
    {
    private:
        std::string bytes;

    public:
        static_assert(constantbytes == crypto_box_NONCEBYTES, "constantbytes needs to be equal to crypto_box_NONCEBYTES");

        source_nonce(const std::string& constant, bool = false)
            : bytes(constant)
        {
            if (constant.size() != constantbytes) {
                throw "constant bytes do not have correct length";
            }
        }
        std::string next()
        {
            return get();
        }
        std::string get() const
        {
            return bytes;
        }
        std::string constant() const { return bytes; }
        std::string sequential() const { return ""; }
    };

    template <unsigned int constantbytes>
    std::ostream& operator<<(std::ostream& s, source_nonce<constantbytes> n)
    {
        s << bin2hex(n.constant());
        return s;
    }

    // ============================================================================================
    // random_nonce
    // Class representing a randomly generated nonce with fixed prefix
    // ============================================================================================

    template <unsigned int constantbytes>
    class random_nonce
    {
    private:
        std::string bytes;

    public:
        static_assert(constantbytes < crypto_box_NONCEBYTES, "constantbytes needs to be less than crypto_box_NONCEBYTES");

        random_nonce(const std::string& constant, bool = false)
            : bytes(constant)
        {
            if (constant.size() != constantbytes) {
                throw "constant bytes do not have correct length";
            }
            bytes.resize(crypto_box_NONCEBYTES, 0);
            randombytes_buf(&bytes[constantbytes], crypto_box_NONCEBYTES - constantbytes);
        }
        std::string next()
        {
            return get();
        }
        std::string get() const
        {
            return bytes;
        }
        std::string constant() const { return bytes.substr(0, constantbytes); }
        std::string sequential() const { return bytes.substr(constantbytes, crypto_box_NONCEBYTES - constantbytes); }
    };

    template <unsigned int constantbytes>
    std::ostream& operator<<(std::ostream& s, random_nonce<constantbytes> n)
    {
        s << bin2hex(n.get());
        return s;
    }

    // ============================================================================================
    // boxer
    // ============================================================================================

    template <typename noncetype>
    class boxer
    {
    private:
        public_key pk_;
        secret_key sk_;
        std::string k_;
        noncetype n_;

    public:
        boxer(const public_key& pk, const secret_key& sk)
            : boxer(pk, sk, "")
        {}

        boxer(const public_key& pk, const secret_key& sk, const std::string& nonce_constant)
            : pk_(pk)
            , sk_(sk)
            , k_(crypto_box_beforenm(pk.get(), sk.get()))
            , n_(nonce_constant, sk.pk.get() > pk.get())
        {}

        ~boxer() {
            memzero(k_);
        }

        std::string nonce_constant() const {
            return n_.constant();
        }

        std::string nonce_sequential() const {
            return n_.sequential();
        }

        std::string box(std::string message)
        {
            std::string c = crypto_box_afternm(message, n_.next(), k_);
#if DEBUG
            std::cout << "box(" << n_ << ", " << bin2hex(message) << ") = " << bin2hex(c) << std::endl;
#endif
            return c;
        }
    };

    // ============================================================================================
    // unboxer
    // ============================================================================================

    template <typename noncetype>
    class unboxer
    {
    private:
        public_key pk_;
        secret_key sk_;
        std::string k_;
        noncetype n_;

    public:
        unboxer(const public_key& pk, const secret_key& sk, const std::string& nonce_constant)
            : pk_(pk)
            , sk_(sk)
            , k_(crypto_box_beforenm(pk.get(), sk.get()))
            , n_(nonce_constant, pk.get() > sk.pk.get())
        {}

        ~unboxer() {
            memzero(k_);
        }

        std::string nonce_constant() const {
            return n_.constant();
        }

        std::string unbox(std::string ciphertext)
        {
            std::string m = crypto_box_open_afternm(ciphertext, n_.next(), k_);
#if DEBUG
            std::cout << "unbox(" << n_ << ", " << bin2hex(ciphertext) << ") = " << bin2hex(m) << std::endl;
#endif
            return m;
        }
    };
} // sodiumpp namespace
