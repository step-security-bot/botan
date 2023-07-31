/**
 * LM-OTS - Leighton-Micali One-Time Signatures
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_LMS_WOTS_H_
#define BOTAN_LMS_WOTS_H_

// TODO: add reference to RFC 8554?
// TODO: NIST SP 800-208 specifies more variants (e.g. SHA-256/192 and SHAKE based). Do we want to support them?
// TODO: what is the difference to "normal" wots?
// i.e. call it LM-OTS in the code (because it is different), or call it wots?

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <botan/hash.h>
#include <botan/strong_type.h>
#include <botan/internal/stl_util.h>

#include <botan/internal/loadstor.h>

namespace Botan {

enum class LMOTS_Algorithm_Type {
   lmots_reserved = 0,
   lmots_sha256_n32_w1 = 1,
   lmots_sha256_n32_w2 = 2,
   lmots_sha256_n32_w4 = 3,
   lmots_sha256_n32_w8 = 4
};

// TODO: from/to LMOTS_Algorithm_Type conversion?
// RFC 8554 4.1
class LMS_Params {
   public:
      LMS_Params(LMOTS_Algorithm_Type type) : hash(HashFunction::create_or_throw("SHA-256")) {
         switch(type) {
            case LMOTS_Algorithm_Type::lmots_sha256_n32_w1:
               w = 1;
               break;
            case LMOTS_Algorithm_Type::lmots_sha256_n32_w2:
               w = 2;
               break;
            case LMOTS_Algorithm_Type::lmots_sha256_n32_w4:
               w = 4;
               break;
            case LMOTS_Algorithm_Type::lmots_sha256_n32_w8:
               w = 8;
               break;
            default:
               BOTAN_ASSERT_UNREACHABLE();
         }
      }

      /**
       * @brief The number of bytes of the output of the hash function.
       */
      size_t n() const { return hash->output_length(); }

      // TODO: make enum? (see also 3.3)
      /**
       * @brief The width (in bits) of the Winternitz coefficients
       *
       */
      uint8_t w;

      /**
       * @brief The number of n-byte string elements that make up the LM-OTS signature.
       *
       * @return size_t
       */
      uint16_t p() const {
         // TODO: compute at construction?
         // TODO: This is fixed for H=SHA-256
         // TODO: generalize (using algo in Appendix B)?
         switch(w) {
            case 1:
               return 265;
            case 2:
               return 133;
            case 4:
               return 67;
            case 8:
               return 34;
         }
         BOTAN_ASSERT_UNREACHABLE();
      };

      /**
       * @brief The number of left-shift bits used in the checksum function Cksm.
       *
       */
      uint8_t ls() const {
         // TODO: compute at construction?
         // TODO: This is fixed for H=SHA-256
         // TODO: generalize (using algo in Appendix B)?
         switch(w) {
            case 1:
               return 7;
            case 2:
               return 6;
            case 4:
               return 4;
            case 8:
               return 0;
         }
         BOTAN_ASSERT_UNREACHABLE();
      };

      std::unique_ptr<HashFunction> hash;
};

// Temporary Strong Types
/// Contains/Is a secret seed used to create the LMS leafs
using WOTS_SEED = Strong<secure_vector<uint8_t>, struct WOTS_SEED_>;
using WOTS_Node = Strong<secure_vector<uint8_t>, struct WOTS_Node_>;
using WOTS_Private_Key = Strong<std::vector<WOTS_Node>, struct WOTS_Private_Key_>;
using WOTS_Public_Key = Strong<std::vector<uint8_t>, struct WOTS_Public_Key_>;
using WOTS_Signature = Strong<std::vector<uint8_t>, struct WOTS_Signature_>;
//using LMS_PublicKey = Strong<std::vector<uint8_t>, struct LMS_PublicKey_>;
// q in RFC
using LMS_Address = Strong<uint32_t, struct LMS_Address_>;

using Message = Strong<std::vector<uint8_t>, struct Message_>;

// I in RFC
using LMS_Identifier = Strong<std::array<uint8_t, 16>, struct LMS_Identifier_>;

// Temp public key
struct LMS_PublicKey {
      std::vector<uint8_t> root;
      std::vector<uint8_t> I;
};

// TODO: move to impl
constexpr uint16_t D_PBLC = 0x8080;

// input: q, I (public key?)
// output: x[0], ..., x[p-1]
// RFC 8554 4.2
WOTS_Private_Key create_private_key(LMS_Params& params,
                                    const LMS_Identifier& identifier,
                                    const LMS_Address& q,
                                    const WOTS_SEED& seed) {
   // We use Pseudorandom Key Generation as defined in Appendix A of RFC 8554

   // I || q || i || 0xff || Seed
   // Prepare the hash input used in the loop, there only the i value is changed
   secure_vector<uint8_t> input_buffer(sizeof(LMS_Identifier) + sizeof(LMS_Address) + sizeof(uint16_t) +
                                       sizeof(uint8_t) + sizeof(WOTS_SEED));  // TODO use constants (maybe in params)
   BufferStuffer input_stuffer(input_buffer);
   input_stuffer.append(std::span(identifier.get()));
   store_be(q.get(), input_stuffer.next(sizeof(LMS_Address)).data());
   std::span<uint8_t> i_buf = input_stuffer.next(sizeof(uint16_t));
   *input_stuffer.next(sizeof(uint8_t)).begin() = 0xff;
   input_stuffer.append(std::span(seed.get()));
   BOTAN_ASSERT_NOMSG(input_stuffer.full());

   WOTS_Private_Key wots_sk(params.p());
   for(uint16_t i = 0; i < params.p(); ++i) {
      store_be(i, i_buf.data());
      wots_sk.get().push_back(params.hash->process<WOTS_Node>(input_buffer));
   }
   return wots_sk;
}

// RFC 8554 4.3
WOTS_Public_Key create_public_key(const LMS_Params& params,
                                  // TODO: should probably be part of WOTS_Private_Key?
                                  const LMS_Identifier& identifier,
                                  // TODO: should probably be part of WOTS_Private_Key?
                                  const LMS_Address& q,
                                  const WOTS_Private_Key& sk) {
   // Prepare part of the hash input used in the loop, there only the i and j value is changed
   secure_vector<uint8_t> input_buffer(sizeof(LMS_Identifier) + sizeof(LMS_Address) + sizeof(uint16_t) +
                                       sizeof(uint8_t));  // TODO use constants (maybe in params)
   BufferStuffer input_stuffer(input_buffer);
   input_stuffer.append(std::span(identifier.get()));
   store_be(q.get(), input_stuffer.next(sizeof(LMS_Address)).data());
   std::span<uint8_t> i_buf = input_stuffer.next(sizeof(uint16_t));
   std::span<uint8_t> j_buf = input_stuffer.next(sizeof(uint8_t));
   BOTAN_ASSERT_NOMSG(input_stuffer.full());

   // Prefill the final hash object
   auto pk_hash = params.hash->new_object();
   pk_hash->update(identifier);
   pk_hash->update_be(q.get());
   pk_hash->update_be(D_PBLC);

   WOTS_Node tmp;
   for(uint16_t i = 0; i < params.p(); ++i) {
      tmp = sk.get().at(i);
      store_be(i, i_buf.data());
      for(uint8_t j = 0; j < ((1 << params.w) - 1) /*TODO: to params*/; ++j) {
         *j_buf.begin() = j;
         params.hash->update(input_buffer);
         params.hash->update(tmp);
         params.hash->final(tmp);
      }
      pk_hash->update(tmp);
   }
   return pk_hash->final<WOTS_Public_Key>();
}

// RFC 8554 3.1.1
uint8_t byte(std::span<uint8_t> S, uint32_t i) {
   BOTAN_ASSERT_NOMSG(i < S.size());
   return S[i];
}

// RFC 8554 3.1.1
uint32_t coef(std::span<uint8_t> S, uint32_t i, uint8_t w) {
   return ((1 << w) - 1) & (byte(S, (i * w) / 8) >> (8 - (w * (i % (8 / w)) + w)));
}

// RFC 8554 4.4

// RFC 8554 4.5
WOTS_Signature generate_signature(const LMS_Params& params,
                                  //  const LMS_Private_Key& sk,
                                  const LMS_PublicKey& pk,
                                  const Message& msg,
                                  const LMS_Address& Q);

}  // namespace Botan

#endif
