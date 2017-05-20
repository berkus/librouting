sodiumpp
========

*This is a very preliminary version, do NOT expect it to be secure or use it for anything important.*

This library implements the C++ API of NaCl on top of libsodium, as well as a high level API that takes care of nonce generation for you:

```c++
#include <sodiumpp.h>
#include <string>
#include <iostream>
using namespace sodiumpp;

int main(int argc, const char ** argv) {
  secret_key sk_client;
  secret_key sk_server;
  
  // Create a nonce type that has a 32-bit sequential counter and constant random bytes for the remaining bytes
  typedef nonce<crypto_box_NONCEBYTES-4, 4> nonce32;
  
  boxer<nonce32> client_boxer(sk_server.pk, sk_client);
  unboxer<nonce32> server_unboxer(sk_client.pk, sk_server, client_boxer.nonce_constant());
  
  std::string boxed = client_boxer.box("Hello, world!");
  std::string unboxed = server_unboxer.unbox(boxed);
  std::cout << unboxed;
  
  boxed = client_boxer.box("From sodiumpp!");
  unboxed = server_unboxer.unbox(boxed);
  std::cout << unboxed;
  
  return 0;
}
```
