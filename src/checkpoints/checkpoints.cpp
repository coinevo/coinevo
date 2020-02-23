// Copyright (c) 2014-2019, The Coinevo Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <vector>

using namespace epee;

#undef COINEVO_DEFAULT_LOG_CATEGORY
#define COINEVO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

/*  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
      ADD_CHECKPOINT(0,     "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
      ADD_CHECKPOINT(1000000, "46b690b710a07ea051bc4a6b6842ac37be691089c0f7758cfeec4d5fc0b4a258");
      ADD_CHECKPOINT(1058600, "12904f6b4d9e60fd875674e07147d2c83d6716253f046af7b894c3e81da7e1bd");
      return true;
    }
    if (nettype == STAGENET)
    {
      ADD_CHECKPOINT(0,       "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb");
      ADD_CHECKPOINT(10000,   "1f8b0ce313f8b9ba9a46108bfd285c45ad7c2176871fd41c3a690d4830ce2fd5");
      return true;
    }
    ADD_CHECKPOINT(1,     "771fbcd656ec1464d3a02ead5e18644030007a0fc664c0a964d30922821a8148");
    ADD_CHECKPOINT(10,    "c0e3b387e47042f72d8ccdca88071ff96bff1ac7cde09ae113dbb7ad3fe92381");
    ADD_CHECKPOINT(100,   "ac3e11ca545e57c49fca2b4e8c48c03c23be047c43e471e1394528b1f9f80b2d");
    ADD_CHECKPOINT(1000,  "5acfc45acffd2b2e7345caf42fa02308c5793f15ec33946e969e829f40b03876");
    ADD_CHECKPOINT(10000, "c758b7c81f928be3295d45e230646de8b852ec96a821eac3fea4daf3fcac0ca2");
    ADD_CHECKPOINT(22231, "7cb10e29d67e1c069e6e11b17d30b809724255fee2f6868dc14cfc6ed44dfb25");
    ADD_CHECKPOINT(29556, "53c484a8ed91e4da621bb2fa88106dbde426fe90d7ef07b9c1e5127fb6f3a7f6");
    ADD_CHECKPOINT(50000, "0fe8758ab06a8b9cb35b7328fd4f757af530a5d37759f9d3e421023231f7b31c");
    ADD_CHECKPOINT(80000, "a62dcd7b536f22e003ebae8726e9e7276f63d594e264b6f0cd7aab27b66e75e3");
    ADD_CHECKPOINT(202612, "bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698");
    ADD_CHECKPOINT(202613, "e2aa337e78df1f98f462b3b1e560c6b914dec47b610698b7b7d1e3e86b6197c2");
    ADD_CHECKPOINT(202614, "c29e3dc37d8da3e72e506e31a213a58771b24450144305bcba9e70fa4d6ea6fb");
    ADD_CHECKPOINT(205000, "5d3d7a26e6dc7535e34f03def711daa8c263785f73ec1fadef8a45880fde8063");
    ADD_CHECKPOINT(220000, "9613f455933c00e3e33ac315cc6b455ee8aa0c567163836858c2d9caff111553");
    ADD_CHECKPOINT(230300, "bae7a80c46859db355556e3a9204a337ae8f24309926a1312323fdecf1920e61");
    ADD_CHECKPOINT(230700, "93e631240ceac831da1aebfc5dac8f722c430463024763ebafa888796ceaeedf");
    ADD_CHECKPOINT(231350, "b5add137199b820e1ea26640e5c3e121fd85faa86a1e39cf7e6cc097bdeb1131");
    ADD_CHECKPOINT(232150, "955de8e6b6508af2c24f7334f97beeea651d78e9ade3ab18fec3763be3201aa8");
    ADD_CHECKPOINT(249380, "654fb0a81ce3e5caf7e3264a70f447d4bd07586c08fa50f6638cc54da0a52b2d");
    ADD_CHECKPOINT(460000, "75037a7aed3e765db96c75bcf908f59d690a5f3390baebb9edeafd336a1c4831");
    ADD_CHECKPOINT(500000, "2428f0dbe49796be05ed81b347f53e1f7f44aed0abf641446ec2b94cae066b02");
    ADD_CHECKPOINT(600000, "f5828ebf7d7d1cb61762c4dfe3ccf4ecab2e1aad23e8113668d981713b7a54c5");
    ADD_CHECKPOINT(700000, "12be9b3d210b93f574d2526abb9c1ab2a881b479131fd0d4f7dac93875f503cd");
    ADD_CHECKPOINT(825000, "56503f9ad766774b575be3aff73245e9d159be88132c93d1754764f28da2ff60");
    ADD_CHECKPOINT(900000, "d9958d0e7dcf91a5a7b11de225927bf7efc6eb26240315ce12372be902cc1337");
    ADD_CHECKPOINT(913193, "5292d5d56f6ba4de33a58d9a34d263e2cb3c6fee0aed2286fd4ac7f36d53c85f");
    ADD_CHECKPOINT(1000000, "a886ef5149902d8342475fee9bb296341b891ac67c4842f47a833f23c00ed721");
    ADD_CHECKPOINT(1100000, "3fd720c5c8b3072fc1ccda922dec1ef25f9ed88a1e6ad4103d0fe00b180a5903");
    ADD_CHECKPOINT(1150000, "1dd16f626d18e1e988490dfd06de5920e22629c972c58b4d8daddea0038627b2");
    ADD_CHECKPOINT(1200000, "fa7d13a90850882060479d100141ff84286599ae39c3277c8ea784393f882d1f");
    ADD_CHECKPOINT(1300000, "31b34272343a44a9f4ac7de7a8fcf3b7d8a3124d7d6870affd510d2f37e74cd0");
    ADD_CHECKPOINT(1390000, "a8f5649dd4ded60eedab475f2bec8c934681c07e3cf640e9be0617554f13ff6c");
    ADD_CHECKPOINT(1450000, "ac94e8860093bc7c83e4e91215cba1d663421ecf4067a0ae609c3a8b52bcfac2");
    ADD_CHECKPOINT(1530000, "01759bce497ec38e63c78b1038892169203bb78f87e488172f6b854fcd63ba7e");
    ADD_CHECKPOINT(1579000, "7d0d7a2346373afd41ed1e744a939fc5d474a7dbaa257be5c6fff4009e789241");
    ADD_CHECKPOINT(1668900, "ac2dcaf3d2f58ffcf8391639f0f1ebafcb8eac43c49479c7c37f611868d07568");
    ADD_CHECKPOINT(1775600, "1c6e01c661dc22cab939e79ec6a5272190624ce8356d2f7b958e4f9a57fdb05e");
    ADD_CHECKPOINT(1856000, "9b57f17f29c71a3acd8a7904b93c41fa6eb8d2b7c73936ce4f1702d14880ba29");
    ADD_CHECKPOINT(1958000, "98a5d6e51afdf3146e0eefb10a66e8648d8d4d5c2742be8835e976ba217c9bb2");
    return true;
  }
*/
bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    switch (nettype) {
      case STAGENET:
        break;
      case TESTNET:
        break;
      case FAKECHAIN:
        break;
      case UNDEFINED:
        break;
      case MAINNET:
#if !defined(EVO_ENABLE_INTEGRATION_TEST_HOOKS)
        ADD_CHECKPOINT(0,      "c106ebad646e2dc0f9ab96741b2c320d3435b43d6f6f9660b1f318f33a764ad2");
        ADD_CHECKPOINT(5,      "40bccdd5ce631f0cc959bb8bf7d3af00c6bae7d93c1a2a9cdcf0d73fb771b8a0");
        ADD_CHECKPOINT(10,     "45f7a39a86145d97f41dbbbc53b45dc40e7f71cd82a631c8d7d28a7e29d6a94c");
        ADD_CHECKPOINT(14,     "3cf3d8e066bee9086e4ae8b8e7e9daa214565fc6819ee458c44fdabc497091bc");
        ADD_CHECKPOINT(18,     "8b064a076d36532d35eae595798021973068d61b893e5ec6f2b07bccd8c54b32");
        ADD_CHECKPOINT(22,     "7b12fac40ea6a4250ec5d6b6f926d5b75b559b6e6d5f0f81323d6095ebae077b");
        ADD_CHECKPOINT(26,     "9033f816ad46136e390e6fbafee962ff616cd66445ed62b86447b20feb5b74ed");
        ADD_CHECKPOINT(30,     "7a22d01f518280d55db3b6276775794b447c52d47ce7170ca6ed7e7959df91e8");
        ADD_CHECKPOINT(35,     "694565f2d416092520f3ec035783983b61c42e22c6c747550ee72c4e9c4f3b3c");
        ADD_CHECKPOINT(38,     "4d2b28fa6db6bf242445460e5a9ecc012d4e6b69a3e4365b8ac7f5ba11ee4559");
        ADD_CHECKPOINT(40,     "93cc7b04ad53df3caa1e9dd251ec711e7772b8edcf50214746978c3f084258e0");
        ADD_CHECKPOINT(45,     "95dce1c3a9ee47cb2bf8cc56730fb4d5ebf4ea3aef9edbf7442f961e5c000b55");
        ADD_CHECKPOINT(50,     "c475bc80a36623a941945353f690025caad5db9df2035a44b7931a21e32c9546");
        ADD_CHECKPOINT(60,     "05936f664158afc7d35f9ae1a1afc6d9c79de96dc9a9e2f0397c126badcdb37d");
        ADD_CHECKPOINT(66,     "c1f1da7a507e4397c6d4e9a7c42e379bafbce33f83ac9d95aea142e0f2940694");
        ADD_CHECKPOINT(69,     "154137a51debfbb46494f5319749e93c88aaa2b14af27feae8336962a1465fd5");
        ADD_CHECKPOINT(70,     "28908e06129e5ce8da5f33f0a0cb84bd07be28b17b8597f17ac0bf060ae3be4c");
        ADD_CHECKPOINT(71,     "8559184e3fb4e21377429fec6c0f50dbc0b3ec675986037242c60a55f6cb6a56");
        ADD_CHECKPOINT(72,     "c3c3b1a29d70c4b2b7b2cae8272bbb63ff33e76b11987aec05286d01707eea2a");
        ADD_CHECKPOINT(78,     "16af409f1d8ca183b565f8a211cd785e45892c51b3b14bf98825591909ed3de0");

#endif
        break;
    }
    return true;
  }

 bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
  LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
  std::string blockhash = it->hash;
  LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
  ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
