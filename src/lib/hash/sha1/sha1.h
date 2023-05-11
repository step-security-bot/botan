/*
* SHA-1
* (C) 1999-2007,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA1_H_
#define BOTAN_SHA1_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* NIST's SHA-1
*/
class SHA_1 final : public HashFunction
   {
   public:
      SHA_1() {}

      std::string name() const override { return "SHA-1"; }
      size_t output_length() const override { return 20; }
      size_t hash_block_size() const override { return 64; }
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

      static void compress_n(uint32_t digest[5], const uint8_t input[], size_t blocks);
      static void init(uint32_t digest[5]);

#if defined(BOTAN_HAS_SHA1_ARMV8)
      static void sha1_armv8_compress_n(uint32_t digest[5],
                                        const uint8_t blocks[],
                                        size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
      static void sse2_compress_n(uint32_t digest[5],
                                  const uint8_t blocks[],
                                  size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
      // Using x86 SHA instructions in Intel Goldmont and Cannonlake
      static void sha1_compress_x86(uint32_t digest[5],
                                    const uint8_t blocks[],
                                    size_t block_count);
#endif

      MD_Hash<MD_Endian::Big, uint32_t, 5, SHA_1::init, SHA_1::compress_n> m_md;
   };

}

#endif
