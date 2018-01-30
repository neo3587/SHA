
#pragma once

#ifndef __NEO_SHA_HPP__
#define __NEO_SHA_HPP__


/*
*	Author: neo3587
*
*	Notes:
*		- Compile with std=c++11 or greater
*/


#include <array>
#include <string>
#include <sstream>
#include <iomanip>

#ifdef _MSC_VER
#include <stdlib.h>
#else
#include <x86intrin.h>
#endif



namespace neo {

	namespace hash {

		template<size_t Bits> 
		struct sha_t : std::array<uint8_t, Bits / 8 + (Bits % 8 != 0)> {

			public:

				static constexpr size_t bits  = Bits;
				static constexpr size_t bytes = Bits / 8 + (Bits % 8 != 0);

				sha_t() {}
				template<class T, size_t N>
				sha_t(const std::array<T, N>& other) : std::array<uint8_t, bytes>(reinterpret_cast<const std::array<uint8_t, bytes>&>(other)) {}
				template<class T>
				sha_t(std::initializer_list<T> il) {
					size_t i = 0;
					for(typename std::initializer_list<T>::iterator it = il.begin(); i < bytes && it != il.end(); ++it)
						for(size_t j = 0; j < sizeof(T); j++, i++)
							(*this)[i] = reinterpret_cast<const uint8_t*>(&*it)[sizeof(T) - j - 1];
					for(; i < bytes; i++)
						(*this)[i] = 0;
				}
				sha_t(const std::string& hex) {
					size_t i = 0;
					for(; i < hex.size() / 2; i++)
						(*this)[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
					if(hex.size() & 1)
						(*this)[i++] = static_cast<uint8_t>(std::stoul(hex.substr(hex.size() - 1, 1), nullptr, 16)) << 4;
					for(; i < bytes; i++)
						(*this)[i] = 0;
				}

				std::string to_str() const {
					std::stringstream ss;
					for(size_t i = 0; i < bytes; i++)
						ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>((*this)[i]);
					return ss.str();
				}

		};

		namespace __sha_details {

			namespace __shared {
				
				template<size_t... Is>
				struct index {};
				template<size_t N, size_t... Is>
				struct gen_seq : gen_seq<N - 1, N - 1, Is...> {};
				template<size_t... Is>
				struct gen_seq<0, Is...> : index<Is...> {
					using type = index<Is...>;
				};
				template<size_t N, size_t... Is>
				struct gen_reverse_seq : gen_reverse_seq<N - 1, sizeof...(Is), Is...> {};
				template<size_t... Is>
				struct gen_reverse_seq<0, Is...> : index<Is...> {
					using type = index<Is...>;
				};

				inline uint32_t _bswap(uint32_t x) {
					#ifdef _MSC_VER
					return _byteswap_ulong(x);
					#else
					return __builtin_bswap32(x);
					#endif
				};
				inline uint64_t _bswap(uint64_t x) {
					#ifdef _MSC_VER
					return _byteswap_uint64(x);
					#else
					return __builtin_bswap64(x);
					#endif
				};
				inline uint32_t _rotrr(uint32_t x, int sh) {
					return _rotr(x, sh);
				}
				inline uint64_t _rotrr(uint64_t x, int sh) {
					#if !defined(_MSC_VER ) && !defined(_rotr64)
					return (x >> sh) | (x << (64 - sh));
					#else
					return _rotr64(x, sh);
					#endif
				}
				inline uint32_t _rotrl(uint32_t x, int sh) {
					return _rotl(x, sh);
				}
				inline uint64_t _rotrl(uint64_t x, int sh) {
					#if !defined(_MSC_VER ) && !defined(_rotl64)
					return (x << sh) | (x >> (64 - sh));
					#else
					return _rotl64(x, sh);
					#endif
				}

				template<size_t Bits, size_t N, size_t... Is>
				inline sha_t<Bits> return_hash(const std::array<uint8_t, N>& hash, index<Is...>) {
					return {hash[Is]...};
				}
				template<size_t Bits, size_t N, size_t... Is>
				inline sha_t<Bits> return_hash(const std::array<uint32_t, N>& hash, index<Is...>) {
					return {hash[Is]...};
				}
				template<size_t Bits, size_t N, size_t... Is>
				inline sha_t<Bits> return_hash(const std::array<uint64_t, N>& hash, index<Is...>) {
					return {reinterpret_cast<const std::array<uint32_t, 16>&>(hash)[Is + !(Is & 1) - (Is & 1)]...};
				}

			}

			namespace __sha1 {

				using namespace neo::hash::__sha_details::__shared;

				struct _sha1_base {

					static sha_t<160> hash(const uint8_t* msg, size_t len) {

						std::array<uint32_t, 5> hash = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

						size_t off;
						for(off = 0; len - off >= 64; off += 64)
							compress(hash, &msg[off]);

						// last block stuff (padding)

						std::array<uint8_t, 64> block = {0};
						size_t lst = len - off;

						std::copy(&msg[off], &msg[off] + lst, block.begin());
						block[lst] = 0x80;

						if(lst >= 56) {
							compress(hash, block.data());
							block.fill(0);
						}

						reinterpret_cast<size_t&>(block[64 - sizeof(size_t)]) = _bswap(len << 3); // 3º
						compress(hash, block.data());

						return return_hash<160>(hash, gen_seq<5>());
					}

					static void compress(std::array<uint32_t, 5>& state, const uint8_t block[64]) {

						// schedule => w
						std::array<uint32_t, 80> schedule;

						//  break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
						for(size_t i = 0; i < 16; i++)
							schedule[i] = _bswap(reinterpret_cast<const uint32_t&>(block[i * sizeof(uint32_t)]));

						// Extend the sixteen 32-bit words into eighty 32-bit words:
						for(size_t i = 16; i < 80; i++)
							schedule[i] = _rotrl(schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1);

						std::array<uint32_t, 5> hbuff = state;

						// main loop
						for(size_t i = 0; i < 4; i++) {
							roundfn_0_20<0, 1, 2, 3, 4>(hbuff, schedule[i * 5 + 0]);
							roundfn_0_20<4, 0, 1, 2, 3>(hbuff, schedule[i * 5 + 1]);
							roundfn_0_20<3, 4, 0, 1, 2>(hbuff, schedule[i * 5 + 2]);
							roundfn_0_20<2, 3, 4, 0, 1>(hbuff, schedule[i * 5 + 3]);
							roundfn_0_20<1, 2, 3, 4, 0>(hbuff, schedule[i * 5 + 4]);
						}
						for(size_t i = 4; i < 8; i++) {
							roundfn_20_40<0, 1, 2, 3, 4>(hbuff, schedule[i * 5 + 0]);
							roundfn_20_40<4, 0, 1, 2, 3>(hbuff, schedule[i * 5 + 1]);
							roundfn_20_40<3, 4, 0, 1, 2>(hbuff, schedule[i * 5 + 2]);
							roundfn_20_40<2, 3, 4, 0, 1>(hbuff, schedule[i * 5 + 3]);
							roundfn_20_40<1, 2, 3, 4, 0>(hbuff, schedule[i * 5 + 4]);
						}
						for(size_t i = 8; i < 12; i++) {
							roundfn_40_60<0, 1, 2, 3, 4>(hbuff, schedule[i * 5 + 0]);
							roundfn_40_60<4, 0, 1, 2, 3>(hbuff, schedule[i * 5 + 1]);
							roundfn_40_60<3, 4, 0, 1, 2>(hbuff, schedule[i * 5 + 2]);
							roundfn_40_60<2, 3, 4, 0, 1>(hbuff, schedule[i * 5 + 3]);
							roundfn_40_60<1, 2, 3, 4, 0>(hbuff, schedule[i * 5 + 4]);
						}
						for(size_t i = 12; i < 16; i++) {
							roundfn_60_80<0, 1, 2, 3, 4>(hbuff, schedule[i * 5 + 0]);
							roundfn_60_80<4, 0, 1, 2, 3>(hbuff, schedule[i * 5 + 1]);
							roundfn_60_80<3, 4, 0, 1, 2>(hbuff, schedule[i * 5 + 2]);
							roundfn_60_80<2, 3, 4, 0, 1>(hbuff, schedule[i * 5 + 3]);
							roundfn_60_80<1, 2, 3, 4, 0>(hbuff, schedule[i * 5 + 4]);
						}

						for(size_t i = 0; i < 5; i++)
							state[i] += hbuff[i];

					}

					template<size_t a, size_t b, size_t c, size_t d, size_t e>
					inline static void roundfn_0_20(std::array<uint32_t, 5>& st, uint32_t w) {
						roundfn_shared<a, b, c, d, e>(st, (st[b] & st[c]) | (~st[b] & st[d]), 0x5A827999, w);
					}
					template<size_t a, size_t b, size_t c, size_t d, size_t e>
					inline static void roundfn_20_40(std::array<uint32_t, 5>& st, uint32_t w) {
						roundfn_shared<a, b, c, d, e>(st, st[b] ^ st[c] ^ st[d], 0x6ED9EBA1, w);
					}
					template<size_t a, size_t b, size_t c, size_t d, size_t e>
					inline static void roundfn_40_60(std::array<uint32_t, 5>& st, uint32_t w) {
						roundfn_shared<a, b, c, d, e>(st, (st[b] & st[c]) | (st[b] & st[d]) | (st[c] & st[d]), 0x8F1BBCDC, w);
					}
					template<size_t a, size_t b, size_t c, size_t d, size_t e>
					inline static void roundfn_60_80(std::array<uint32_t, 5>& st, uint32_t w) {
						roundfn_shared<a, b, c, d, e>(st, st[b] ^ st[c] ^ st[d], 0xCA62C1D6, w);
					}
					template<size_t a, size_t b, size_t c, size_t d, size_t e>
					inline static void roundfn_shared(std::array<uint32_t, 5>& st, uint32_t f, uint32_t k, uint32_t w) {
						st[e] = _rotrl(st[a], 5) + f + st[e] + k + w;
						st[b] = _rotrl(st[b], 30);
					}

				};

			}
			namespace __sha2 {

				using namespace neo::hash::__sha_details::__shared;

				template<class T, size_t Bits>
				constexpr std::array<T, 8> init_hash() {
					throw "Base method called";
				}
				template<> constexpr std::array<uint32_t, 8> init_hash<uint32_t, 224>() { // sha224
					return {
						0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
						0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
					};
				};
				template<> constexpr std::array<uint32_t, 8> init_hash<uint32_t, 256>() { // sha256
					return {
						0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
						0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
					};
				};
				template<> constexpr std::array<uint64_t, 8> init_hash<uint64_t, 384>() { // sha384
					return {
						0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
						0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
					};
				}
				template<> constexpr std::array<uint64_t, 8> init_hash<uint64_t, 512>() { // sha512
					return {
						0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
						0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
					};
				}
				template<> constexpr std::array<uint64_t, 8> init_hash<uint64_t, 224>() { // sha512/224
					return {
						0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
						0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
					};
				}
				template<> constexpr std::array<uint64_t, 8> init_hash<uint64_t, 256>() { // sha512/256
					return {
						0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
						0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2
					};
				}

				template<class T, size_t N>
				constexpr std::array<T, N> get_round_table() {
					throw "Base method called";
				}
				template<> constexpr std::array<uint32_t, 64> get_round_table<uint32_t, 64>() { // sha224/256
					return {
						0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
						0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
						0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
						0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
						0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
						0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
						0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
						0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
					};
				}
				template<> constexpr std::array<uint64_t, 80> get_round_table<uint64_t, 80>() { // sha384/512
					return {
						0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,	0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
						0xD807AA98A3030242, 0x12835B0145706FBE,	0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,	0xC19BF174CF692694,
						0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
						0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
						0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
						0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
						0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
						0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC, 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
						0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
						0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
					};
				}

				template<class T>
				constexpr std::array<int, 12> unique_vals() {
					throw "Base method called";
				}
				template<> constexpr std::array<int, 12> unique_vals<uint32_t>() {
					return {
						7, 18, 3, 17, 19, 10,
						6, 11, 25, 2, 13, 22
					};
				}
				template<> constexpr std::array<int, 12> unique_vals<uint64_t>() {
					return {
						1, 8, 7, 19, 61, 6,
						14, 18, 41, 28, 34, 39
					};
				}

				template<class T, size_t Bits, size_t Rounds, size_t Blk>
				struct _sha2_base {

					static constexpr std::array<int, 12> seq = unique_vals<T>();

					static sha_t<Bits> hash(const uint8_t* msg, size_t len) {

						std::array<T, 8> hash = init_hash<T, Bits>();

						size_t off;
						for(off = 0; len - off >= Blk; off += Blk)
							compress(hash, &msg[off]);

						// last block stuff (padding)

						std::array<uint8_t, Blk> block = {0};
						size_t lst = len - off;

						std::copy(&msg[off], &msg[off] + lst, block.begin());
						block[lst] = 0x80;

						if(lst >= Blk - 8) {
							compress(hash, block.data());
							block.fill(0);
						}

						reinterpret_cast<size_t&>(block[Blk - sizeof(size_t)]) = _bswap(len << 3); // 3º
						compress(hash, block.data());

						return return_hash<Bits>(hash, gen_seq<Bits / 32>());
					}

					static void compress(std::array<T, 8>& state, const uint8_t block[Blk]) {

						// round_table => k
						static constexpr std::array<T, Rounds> round_table = get_round_table<T, Rounds>();

						// schedule => w
						std::array<T, Rounds> schedule;

						// copy chunk into first 16 words w[0,16) of the message schedule array, big-endian encoding
						for(size_t i = 0; i < 16; i++)
							schedule[i] = _bswap(reinterpret_cast<const T&>(block[i * sizeof(T)]));

						// first 16 words expansion to [16,64/80)
						for(size_t i = 16; i < Rounds; i++)
							schedule[i] = schedule[i - 16] + schedule[i - 7]
							+ (_rotrr(schedule[i - 15], seq[0]) ^ _rotrr(schedule[i - 15], seq[1]) ^ (schedule[i - 15] >> seq[2]))
							+ (_rotrr(schedule[i - 2], seq[3]) ^ _rotrr(schedule[i - 2], seq[4]) ^ (schedule[i - 2] >> seq[5]));

						std::array<T, 8> hbuff = state;

						// main compression loop (64/80 rounds)
						for(size_t i = 0; i < Rounds / 8; i++) {
							round_fn<0, 1, 2, 3, 4, 5, 6, 7>(hbuff, schedule[i * 8 + 0], round_table[i * 8 + 0]);
							round_fn<7, 0, 1, 2, 3, 4, 5, 6>(hbuff, schedule[i * 8 + 1], round_table[i * 8 + 1]);
							round_fn<6, 7, 0, 1, 2, 3, 4, 5>(hbuff, schedule[i * 8 + 2], round_table[i * 8 + 2]);
							round_fn<5, 6, 7, 0, 1, 2, 3, 4>(hbuff, schedule[i * 8 + 3], round_table[i * 8 + 3]);
							round_fn<4, 5, 6, 7, 0, 1, 2, 3>(hbuff, schedule[i * 8 + 4], round_table[i * 8 + 4]);
							round_fn<3, 4, 5, 6, 7, 0, 1, 2>(hbuff, schedule[i * 8 + 5], round_table[i * 8 + 5]);
							round_fn<2, 3, 4, 5, 6, 7, 0, 1>(hbuff, schedule[i * 8 + 6], round_table[i * 8 + 6]);
							round_fn<1, 2, 3, 4, 5, 6, 7, 0>(hbuff, schedule[i * 8 + 7], round_table[i * 8 + 7]);
						}

						for(size_t i = 0; i < 8; i++)
							state[i] += hbuff[i];

					}

					template<size_t a, size_t b, size_t c, size_t d, size_t e, size_t f, size_t g, size_t h>
					inline static void round_fn(std::array<T, 8>& st, T w, T k) {
						T tmp = (_rotrr(st[e], seq[6]) ^ _rotrr(st[e], seq[7]) ^ _rotrr(st[e], seq[8])) + ((st[e] & st[f]) ^ (~st[e] & st[g])) + w + k;
						st[d] += tmp + st[h];
						st[h] += tmp + (_rotrr(st[a], seq[9]) ^ _rotrr(st[a], seq[10]) ^ _rotrr(st[a], seq[11])) + ((st[a] & st[b]) ^ (st[a] & st[c]) ^ (st[b] & st[c]));
					}

				};

			}
			namespace __sha3 {

				using namespace neo::hash::__sha_details::__shared;

				template<size_t Bits, size_t Bitrate, size_t Capacity, uint8_t Delimiter>
				struct _sha3_base {

					static constexpr size_t blk_size = Bitrate / 8;

					typedef union {
						std::array<std::array<uint64_t, 5>, 5> a_u64;
						std::array<uint64_t, 25> u64;
						std::array<uint8_t, 200> u8;
					} state_t;

					static sha_t<Bits> hash(const uint8_t* msg, size_t len) {

						state_t state;
						sponge(state, msg, len);

						return return_hash<Bits>(state.u8, gen_seq<Bits / 8>());
					}
					static sha_t<Bits> hash_shake(const uint8_t* msg, size_t len) {

						state_t state;
						sponge(state, msg, len);
						
						// squeeze 
						std::array<uint8_t, Bits / 8> out;
						for(size_t i = 0; i < Bits / 8; i += 200) {
							for(size_t j = i; j < i + 200 && j + i < Bits / 8; j++)
								out[j] = state.u8[j];
							permute(state.a_u64);
						}

						return return_hash<Bits>(out, gen_seq<Bits / 8>());
					}

					static void sponge(state_t& state, const uint8_t* msg, size_t len) {
						
						state.u64.fill(0);

						size_t off;
						for(off = 0; len - off >= blk_size; off += blk_size) {
							for(size_t i = 0; i < blk_size; i++)
								state.u8[i] ^= msg[off + i];
							permute(state.a_u64);
						}

						size_t lst = len - off;
						for(size_t i = 0; i < lst; i++)
							state.u8[i] ^= msg[off + i];

						state.u8[lst] ^= Delimiter;
						state.u8[blk_size - 1] ^= 0x80;
						permute(state.a_u64);
					}
					static void permute(std::array<std::array<uint64_t, 5>, 5>& a) {

						static constexpr std::array<uint64_t, 24> round_consts = {
							0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
							0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
							0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
							0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
							0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
							0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
						};
						static constexpr std::array<std::array<int, 5>, 5> rot_offs = {{
							{ 0,  1, 62, 28, 27},
							{36, 44,  6, 55, 20},
							{ 3, 10, 43, 25, 39},
							{41, 45, 15, 21,  8},
							{18,  2, 61, 56, 14}
						}};

						std::array<std::array<uint64_t, 5>, 5> b;
						std::array<uint64_t, 5> c;

						for(size_t rd = 0; rd < 24; rd++) {

							// theta
							for(size_t x = 0; x < 5; x++)
								c[x] = a[0][x] ^ a[1][x] ^ a[2][x] ^ a[3][x] ^ a[4][x];
							for(size_t x = 0; x < 5; x++) {
								uint64_t dx = c[(x + 4) % 5] ^ _rotrl(c[(x + 1) % 5], 1);
								for(size_t y = 0; y < 5; y++)
									a[y][x] ^= dx;
							}

							// rho & pi
							for(size_t y = 0; y < 5; y++)
								for(size_t x = 0; x < 5; x++)
									b[(x * 2 + y * 3) % 5][y] = _rotrl(a[y][x], rot_offs[y][x]);

							// chi
							for(size_t y = 0; y < 5; y++)
								for(size_t x = 0; x < 5; x++)
									a[y][x] = b[y][x] ^ (~b[y][(x + 1) % 5] & b[y][(x + 2) % 5]);

							// iota
							a[0][0] ^= round_consts[rd];

						}

					}

				};

			}

		}


		class sha1 {

			public:

				template<class T> inline static sha_t<160> hash(const T* msg, size_t byte_len) {
					return __sha_details::__sha1::_sha1_base::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}

		};
		class sha2 {

			public:

				template<class T> inline static sha_t<224> hash_224(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint32_t, 224, 64, 64>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<256> hash_256(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint32_t, 256, 64, 64>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<384> hash_384(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint64_t, 384, 80, 128>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<512> hash_512(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint64_t, 512, 80, 128>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<224> hash_512_224(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint64_t, 224, 80, 128>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<256> hash_512_256(const T* msg, size_t byte_len) {
					return __sha_details::__sha2::_sha2_base<uint64_t, 256, 80, 128>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}

		};
		class sha3 {
		
			public:

				template<class T> inline static sha_t<224> hash_224(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<224, 1152, 448, 0x06>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<256> hash_256(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<256, 1088, 512, 0x06>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<384> hash_384(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<384, 832, 768, 0x06>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<class T> inline static sha_t<512> hash_512(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<512, 576, 1024, 0x06>::hash(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}

				template<size_t Bits, class T>
				inline static sha_t<Bits> hash_shake_128(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<Bits, 1344, 256, 0x1f>::hash_shake(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}
				template<size_t Bits, class T>
				inline static sha_t<Bits> hash_shake_256(const T* msg, size_t byte_len) {
					return __sha_details::__sha3::_sha3_base<Bits, 1088, 512, 0x1f>::hash_shake(reinterpret_cast<const uint8_t*>(msg), byte_len);
				}

		};

	}

}



#endif

