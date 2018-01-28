# SHA

A simple SHA hash function variations implementation for C++


TODO:
  - SHA3


Usage example:

```c++
#include "sha.hpp"

#include <iostream>
#include <string>
#include <vector>


using std::cout;
using std::endl;

using namespace neo::hash;



int main(int argc, char* argv[]) {

	std::string msg = "The quick brown fox jumps over the lazy dog";

	cout << "sha2-224:     " << sha2::hash_224((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-256:     " << sha2::hash_256((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-384:     " << sha2::hash_384((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512:     " << sha2::hash_512((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512/224: " << sha2::hash_512_224((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512/256: " << sha2::hash_512_256((uint8_t*)msg.c_str(), msg.size()).to_str() << endl;

	return 0;
}
```

