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

#include <sodiumpp/sodiumpp.h>
#include <string>
#include <iostream>
using namespace sodiumpp;
using namespace std;

int main(int argc, const char ** argv) {
    box_secret_key sk_client;
    box_secret_key sk_server;

    cout << "Client key: " << sk_client << endl;
    cout << "Server key: " << sk_server << endl;
    cout << endl;

    // Uses predefined nonce type with 64-bit sequential counter 
    // and constant random bytes for the rest
    boxer<nonce64> client_boxer(sk_server.pk, sk_client);
    unboxer<nonce64> server_unboxer(sk_client.pk, sk_server, client_boxer.get_nonce_constant());

    nonce64 used_n;
    encoded_bytes boxed = client_boxer.box("Hello, world!\n", used_n);
    cout << "Nonce (hex): " << used_n.get(encoding::hex).bytes << endl;
    cout << "Boxed message (z85): " << boxed.to(encoding::z85).bytes << endl;
    // Nonce is passed explicitly here, but will also be increased automatically
    // if unboxing happens in the same order as boxing.
    // In a real application this nonce would be passed along with the boxed message.
    string unboxed = server_unboxer.unbox(boxed, used_n);
    cout << "Unboxed message: " << unboxed;
    cout << endl;

    // Box with server private key for client public key to unbox.
    boxer<nonce64> server_boxer(sk_client.pk, sk_server);
    // Unbox with client private key and passed server nonce.
    unboxer<nonce64> client_unboxer(sk_server.pk, sk_client, server_boxer.get_nonce_constant());

    boxed = server_boxer.box("From sodiumpp!\n", used_n);
    unboxed = client_unboxer.unbox(boxed, used_n);
    cout << "Nonce (hex): " << used_n.get(encoding::hex).bytes << endl;
    cout << "Boxed message (z85): " << boxed.to(encoding::z85).bytes << endl;
    cout << "Unboxed message: " << unboxed;
    return 0;
}
