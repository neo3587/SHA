# SHA

A simple SHA hash function variations implementation for C++



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

	cout << "sha1:          " << sha1::hash(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-224:      " << sha2::hash_224(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-256:      " << sha2::hash_256(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-384:      " << sha2::hash_384(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512:      " << sha2::hash_512(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512/224:  " << sha2::hash_512_224(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha2-512/256:  " << sha2::hash_512_256(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha3-224:      " << sha3::hash_224(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha3-256:      " << sha3::hash_256(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha3-384:      " << sha3::hash_384(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha3-512:      " << sha3::hash_512(msg.c_str(), msg.size()).to_str() << endl;
	cout << "sha3-shake128: " << sha3::hash_shake_128<256>(msg.c_str(), msg.size()).to_str() << endl; // variable bit len output
	cout << "sha3-shake256: " << sha3::hash_shake_256<512>(msg.c_str(), msg.size()).to_str() << endl; // variable bit len output

	return 0;
}
```

