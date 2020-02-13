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
/*        ADD_CHECKPOINT(5,      "786a14dc9ba1d9d70e1dca717f17d160a49180eeefcb85d02815da827f076052");
        ADD_CHECKPOINT(10,     "972e4fad4c5fee4cecb86f86f0b91fdd432da513c5dc5e74ab2fe943c5cbfb23");
        ADD_CHECKPOINT(15,     "b221735a4db5a3ed99b8b972125763dfaa56b63cb34b59fdc067ec6056845ade");
        ADD_CHECKPOINT(20,     "08ffcca87bb07b74158763fa8ee42a7c751d41d273a94b10d093f813d238673a");
        ADD_CHECKPOINT(100,    "cde26b401437dae9a1303fc3741f1ea4b824a913c33f81c4d790d1446ee307a3");
        ADD_CHECKPOINT(150,    "2b860d064e971b93a10b5c1c2ee87ec5e921684e51501edae097c4f12eede7e4");
        ADD_CHECKPOINT(200,    "b65fa27d92db39b5170d600a9aff1ae9da1bfb605ace1aca5cd1f7763a9f92b0");
        ADD_CHECKPOINT(201,    "0b14052ccead848f3d2a2219f8d0289bcab93c930f9dc0283c6812e971447a58");
        ADD_CHECKPOINT(217,    "6dd54725d3db6df4d6f48743c8cfb3cf40076b4e02803a3780305e7e29388d57");
        ADD_CHECKPOINT(225,    "39bff96fed77c42689a411cde77a33a1f86b38d11c925d115546be5fbce927c0");
        ADD_CHECKPOINT(230,    "d86857ebb5b0d2021e45fda248a532e4b53b5aaaf3016f4e560c1273e8d98fbd");
        ADD_CHECKPOINT(239,    "1ee29f877aa3818f668d338bd780bbb925e761cbcf845cf1f1f93844f74b96c0");
        ADD_CHECKPOINT(240,    "dd530b807103b41db888890c09e517e2e5aa6e4b02ac30b865b736c5ee5769bd");
        ADD_CHECKPOINT(250,    "d44b7cef11ed56cb836c1f2ebf7f7b140125f988f47a09bf36a7062a302eb404");
        ADD_CHECKPOINT(260,    "33df07387be685b1536e9274d4fc0fb4946d388af6f0d6ca2a31e10cca658319");
        ADD_CHECKPOINT(280,    "189b2228155f149d40da2032ac076584674299d50e7844ce34d7b012687e3158");
        ADD_CHECKPOINT(290,    "397a80f4ff7bc090b54c89865c61ca5212b37df3b61efaf627cad482e45c1d70");
        ADD_CHECKPOINT(295,    "aa995e2cbcdf49046e834edd47c9499ff1c57c98dbc57e72ca533efb4224bbc4");
        ADD_CHECKPOINT(300,    "64618f1f3dc415a105f8080086a5904da13690429fcf17e2da5d1fefdf4e89f2");
        ADD_CHECKPOINT(303,    "429041f2f4cae95b2bb55bdaf12dd5e8ce9e051fbbdd316795566fb5a7c8c8cf");
*/

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
