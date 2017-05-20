//  example.cpp
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

#include "sodiumpp.h"
#include <string>
#include <iostream>
using namespace sodiumpp;
using namespace std;

int main(int argc, const char ** argv) {
    secret_key sk_client;
    secret_key sk_server;

    cout << "Server " << sk_server << endl;
    cout << "Client " << sk_client << endl;

    // Create a nonce type that has a 64-bit sequential counter and constant random bytes for the remaining bytes
    typedef nonce<crypto_box_NONCEBYTES-8, 8> nonce64;

    // Box with client private key for server public key to unbox.
    boxer<nonce64> client_boxer(sk_server.pk, sk_client);
    // Unbox with server private key and passed client nonce.
    unboxer<nonce64> server_unboxer(sk_client.pk, sk_server, client_boxer.nonce_constant());

    string boxed = client_boxer.box("Hello, world!\n");
    cout << bin2hex(boxed) << endl;
    string unboxed = server_unboxer.unbox(boxed);
    cout << unboxed;

    // Box with server private key for client public key to unbox.
    boxer<nonce64> server_boxer(sk_client.pk, sk_server);
    // Unbox with client private key and passed server nonce.
    unboxer<nonce64> client_unboxer(sk_server.pk, sk_client, server_boxer.nonce_constant());

    boxed = server_boxer.box("From sodiumpp!\n");
    cout << bin2hex(boxed) << endl;
    unboxed = client_unboxer.unbox(boxed);
    cout << unboxed;
    return 0;
}
