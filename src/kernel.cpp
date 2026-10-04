// Copyright (c) 2012-2025 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel.h>
#include <chainparams.h>
#include <validation.h>
#include <streams.h>
#include <timedata.h>
#include <bignum.h>
#include <txdb.h>
#include <consensus/validation.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <random.h>
#include <script/interpreter.h>

#include <index/txindex.h>

#include <algorithm>
#include <array>

using namespace std;

uint256 Kernel::StakeKernelHashInputs::GetHash() const
{
    CDataStream stream{SER_GETHASH, 0};
    if (use_stake_modifier) {
        stream << nStakeModifier;
    } else {
        stream << nBits;
    }
    stream << nTimeBlockFrom << nTxPrevOffset << nTimeTxPrev << nPrevOutput << nTimeTx;
    return Hash(stream);
}

// Protocol switch time of v0.3 kernel protocol
unsigned int nProtocolV03SwitchTime     = 1363800000;
unsigned int nProtocolV03TestSwitchTime = 1359781000;
// Protocol switch time of v0.4 kernel protocol
unsigned int nProtocolV04SwitchTime     = 1399300000;
unsigned int nProtocolV04TestSwitchTime = 1395700000;
// Protocol switch time of v0.5 kernel protocol
unsigned int nProtocolV05SwitchTime     = 1461700000;
unsigned int nProtocolV05TestSwitchTime = 1447700000;
// Protocol switch time of v0.6 kernel protocol
// supermajority hardfork: actual fork will happen later than switch time
const unsigned int nProtocolV06SwitchTime     = 1513050000; // Tue 12 Dec 03:40:00 UTC 2017
const unsigned int nProtocolV06TestSwitchTime = 1508198400; // Tue 17 Oct 00:00:00 UTC 2017
// Protocol switch time for 0.7 kernel protocol
const unsigned int nProtocolV07SwitchTime     = 1552392000; // Tue 12 Mar 12:00:00 UTC 2019
const unsigned int nProtocolV07TestSwitchTime = 1541505600; // Tue 06 Nov 12:00:00 UTC 2018
// Switch time for new BIPs from bitcoin 0.16.x
const uint32_t nBTC16BIPsSwitchTime           = 1569931200; // Tue 01 Oct 12:00:00 UTC 2019
const uint32_t nBTC16BIPsTestSwitchTime       = 1554811200; // Tue 09 Apr 12:00:00 UTC 2019
// Protocol switch time for v0.9 kernel protocol
const unsigned int nProtocolV09SwitchTime     = 1591617600; // Mon  8 Jun 12:00:00 UTC 2020
const unsigned int nProtocolV09TestSwitchTime = 1581940800; // Mon 17 Feb 12:00:00 UTC 2020
// Protocol switch time for v10 kernel protocol
const unsigned int nProtocolV10SwitchTime     = 1635768000; // Mon  1 Nov 12:00:00 UTC 2021
const unsigned int nProtocolV10TestSwitchTime = 1625140800; // Thu  1 Jul 12:00:00 UTC 2021
// Protocol switch time for v12 kernel protocol
const unsigned int nProtocolV12SwitchTime     = 1700276331; // Sat 18 Nov 02:58:51 UTC 2023
const unsigned int nProtocolV12TestSwitchTime = 1671060214; // Wed 14 Dec 11:23:34 UTC 2022
// Protocol switch time for v14 kernel protocol
const unsigned int nProtocolV14SwitchTime     = 1717416000; // Mon  3 Jun 12:00:00 UTC 2024
const unsigned int nProtocolV14TestSwitchTime = 1710720000; // Mon 18 Mar 00:00:00 UTC 2024
// Protocol switch time for v15 kernel protocol
const unsigned int nProtocolV15SwitchTime     = 1741780800; // Wed 12 Mar 12:00:00 UTC 2025
const unsigned int nProtocolV15TestSwitchTime = 1734004800; // Thu 12 Dec 12:00:00 UTC 2024

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints = {
    { 0, 0x0e00670bu },
    { 19080, 0xad4e4d29u },
    { 30583, 0xdc7bf136u },
    { 99999, 0xf555cfd2u },
    { 219999, 0x91b7444du },
    { 336000, 0x6c3c8048u },
    { 371850, 0x9b850bdfu },
    { 407813, 0x46fe50b5u },
    { 443561, 0x114a6e38u },
    { 455470, 0x9b7af181u },
    { 479189, 0xe04fb8e0u },
    { 504051, 0x459f5a16u },
    { 589659, 0xbd02492au },
    { 714688, 0xd70a5b68u },
    { 770396, 0x565fb851u },
    { 801334, 0x90485c37u },
};

static std::map<int, unsigned int> mapStakeModifierTestnetCheckpoints = {
    { 0, 0x0e00670bu },
    { 19080, 0x3711dc3au },
    { 30583, 0xb480fadeu },
    { 99999, 0x9a62eaecu },
    { 219999, 0xeafe96c3u },
    { 336000, 0x8330dc09u },
    { 372751, 0xafb94e2fu },
    { 382019, 0x7f5cf5ebu },
    { 408500, 0x68cadee2u },
    { 412691, 0x93138e67u },
    { 441299, 0x03e195cbu },
    { 442735, 0xe42d94feu },
    { 516308, 0x04a0897au },
    { 573702, 0xe69df1acu },
    { 612778, 0x6be16d62u },
};

// Whether the given coinstake is subject to new v0.3 protocol
bool IsProtocolV03(unsigned int nTimeCoinStake)
{
    return (nTimeCoinStake >= (Params().GetChainTypeString() != "main" ? nProtocolV03TestSwitchTime : nProtocolV03SwitchTime));
}

// Whether the given block is subject to new v0.4 protocol
bool IsProtocolV04(unsigned int nTimeBlock)
{
    return (nTimeBlock >= (Params().GetChainTypeString() != "main" ? nProtocolV04TestSwitchTime : nProtocolV04SwitchTime));
}

// Whether the given transaction is subject to new v0.5 protocol
bool IsProtocolV05(unsigned int nTimeTx)
{
    return (nTimeTx >= (Params().GetChainTypeString() != "main" ? nProtocolV05TestSwitchTime : nProtocolV05SwitchTime));
}

// Whether a given block is subject to new v0.6 protocol
// Test against previous block index! (always available)
bool IsProtocolV06(const CBlockIndex* pindexPrev)
{
  if (Params().GetChainTypeString() == "regtest")
      return true;

  if (pindexPrev->nTime < (Params().GetChainTypeString() != "main" ? nProtocolV06TestSwitchTime : nProtocolV06SwitchTime))
    return false;

  // if 900 of the last 1,000 blocks are version 2 or greater (90/100 if testnet):
  // Soft-forking PoS can be dangerous if the super majority is too low
  // The stake majority will decrease after the fork
  // since only coindays of updated nodes will get destroyed.
  if ((Params().GetChainTypeString() == "main" && pindexPrev->nHeight > 339678) ||
      (Params().GetChainTypeString() != "main" && pindexPrev->nHeight > 301251))
    return true;

  return false;
}

// Whether a given transaction is subject to new v0.7 protocol
bool IsProtocolV07(unsigned int nTimeTx)
{
    bool fTestNet = Params().GetChainTypeString() != "main";
    return (nTimeTx >= (fTestNet? nProtocolV07TestSwitchTime : nProtocolV07SwitchTime));
}

bool IsBTC16BIPsEnabled(uint32_t nTimeTx)
{
    if (Params().GetChainTypeString() == "regtest") return true;
    bool fTestNet = Params().GetChainTypeString() != "main";
    return (nTimeTx >= (fTestNet? nBTC16BIPsTestSwitchTime : nBTC16BIPsSwitchTime));
}

// Whether a given timestamp is subject to new v0.9 protocol
bool IsProtocolV09(unsigned int nTime)
{
  return (nTime >= (Params().GetChainTypeString() != "main" ? nProtocolV09TestSwitchTime : nProtocolV09SwitchTime));
}

// Whether a given timestamp is subject to new v10 protocol
bool IsProtocolV10(unsigned int nTime)
{
  return (nTime >= (Params().GetChainTypeString() != "main" ? nProtocolV10TestSwitchTime : nProtocolV10SwitchTime));
}

// Whether a given block is subject to new v12 protocol
bool IsProtocolV12(const CBlockIndex* pindexPrev)
{
  if (Params().GetChainTypeString() == "regtest")
      return true;

  return (pindexPrev->nTime >= (Params().GetChainTypeString() != "main" ? nProtocolV12TestSwitchTime : nProtocolV12SwitchTime));
}

// Whether a given block is subject to new v14 protocol
bool IsProtocolV14(const CBlockIndex* pindexPrev)
{
  if (Params().GetChainTypeString() == "regtest")
      return true;

  if (pindexPrev->nTime < (Params().GetChainTypeString() != "main" ? nProtocolV14TestSwitchTime : nProtocolV14SwitchTime))
      return false;

  if ((Params().GetChainTypeString() == "main" && pindexPrev->nHeight > 770395) ||
      (Params().GetChainTypeString() != "main" && pindexPrev->nHeight > 573706))
    return true;

  return false;
}

// Whether a given block is subject to new v15 protocol
bool IsProtocolV15(const CBlockIndex* pindexPrev)
{
  if (Params().GetChainTypeString() == "regtest")
      return true;

  if (pindexPrev->nTime < (Params().GetChainTypeString() != "main" ? nProtocolV15TestSwitchTime : nProtocolV15SwitchTime))
      return false;

  if ((Params().GetChainTypeString() == "main" && pindexPrev->nHeight > 801330) ||
      (Params().GetChainTypeString() != "main" && pindexPrev->nHeight > 612775))
    return true;

  return false;
}

// Get the last stake modifier and its generation time from a given block
#include <logging.h>
#define error(...) (LogPrintf(__VA_ARGS__), false) // peercoin bridge

static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

namespace {

struct StakeModifierSelectionParams {
    std::array<int64_t, 64> sections{};
    int64_t interval{0};
    int64_t modifier_interval;
    int64_t target_spacing;

    explicit StakeModifierSelectionParams(const Consensus::Params& params)
        : modifier_interval{params.nModifierInterval}, target_spacing{params.nStakeTargetSpacing}
    {
        for (size_t section = 0; section < sections.size(); ++section) {
            const int64_t section_index{static_cast<int64_t>(section)};
            sections[section] = params.nModifierInterval * 63 /
                (63 + ((63 - section_index) * (MODIFIER_INTERVAL_RATIO - 1)));
            interval += sections[section];
        }
    }
};

/** A block participating in stake-modifier selection.
 *
 * All values used by the selection rounds are captured once so that selection
 * is independent of block-index lookups and does not repeatedly hash the same
 * candidate.
 */
struct StakeModifierCandidate {
    int height;
    int64_t time;
    uint256 block_hash;
    bool proof_of_stake;
    unsigned int entropy_bit;
    arith_uint256 selection_hash;

    StakeModifierCandidate(const CBlockIndex& index, uint64_t previous_modifier)
        : height{index.nHeight},
          time{index.GetBlockTime()},
          block_hash{index.GetBlockHash()},
          proof_of_stake{index.IsProofOfStake()},
          entropy_bit{index.GetStakeEntropyBit()}
    {
        const uint256 hash_proof{proof_of_stake ? index.hashProofOfStake : block_hash};
        CDataStream stream{SER_GETHASH, 0};
        stream << hash_proof << previous_modifier;
        selection_hash = UintToArith256(Hash(stream));

        // Favor proof-of-stake candidates to preserve the energy-efficiency
        // property of the original selection algorithm.
        if (proof_of_stake) selection_hash >>= 32;
    }
};

class StakeModifierSelection {
public:
    StakeModifierSelection(const Consensus::Params& params, const CBlockIndex& previous,
                           uint64_t previous_modifier)
        : m_params{params}, m_previous_height{previous.nHeight}
    {
        Collect(previous, previous_modifier);
    }

    void Select()
    {
        m_interval_stop = m_interval_start;
        m_selected_count = std::min(m_params.sections.size(), m_candidates.size());

        for (size_t round = 0; round < m_selected_count; ++round) {
            m_interval_stop += m_params.sections[round];

            // Earlier winners occupy [0, round). The remaining range stays in
            // timestamp/hash order after each rotation.
            size_t selected = round;
            for (size_t candidate = round + 1; candidate < m_candidates.size(); ++candidate) {
                if (m_candidates[candidate].time > m_interval_stop) break;
                if (m_candidates[candidate].selection_hash < m_candidates[selected].selection_hash) {
                    selected = candidate;
                }
            }

            auto begin = m_candidates.begin() + round;
            std::rotate(begin, m_candidates.begin() + selected, m_candidates.begin() + selected + 1);
        }
    }

    uint64_t ComputeModifier() const
    {
        uint64_t modifier{0};
        for (size_t round = 0; round < m_selected_count; ++round) {
            modifier |= uint64_t{m_candidates[round].entropy_bit} << round;
        }
        return modifier;
    }

    void Log() const
    {
        int64_t interval_stop{m_interval_start};
        for (size_t round = 0; round < m_selected_count; ++round) {
            interval_stop += m_params.sections[round];
            const auto& candidate = m_candidates[round];
            LogPrintf("SelectBlockFromCandidates: selection hash=%s\n", candidate.selection_hash.ToString());
            LogPrintf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n",
                static_cast<int>(round), FormatISO8601DateTime(interval_stop), candidate.height, candidate.entropy_bit);
        }

        std::string selection_map(m_previous_height - m_first_height + 1, '-');
        for (const auto& candidate : m_candidates) {
            if (candidate.proof_of_stake) {
                selection_map.replace(candidate.height - m_first_height, 1, "=");
            }
        }
        for (size_t round = 0; round < m_selected_count; ++round) {
            const auto& candidate = m_candidates[round];
            selection_map.replace(candidate.height - m_first_height, 1,
                candidate.proof_of_stake ? "S" : "W");
        }
        LogPrintf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n",
            m_first_height, m_previous_height, selection_map);
    }

private:
    void Collect(const CBlockIndex& previous, uint64_t previous_modifier)
    {
        m_interval_start = (previous.GetBlockTime() / m_params.modifier_interval) *
            m_params.modifier_interval - m_params.interval;
        m_candidates.reserve(64 * m_params.modifier_interval / m_params.target_spacing);

        const CBlockIndex* index{&previous};
        while (index && index->GetBlockTime() >= m_interval_start) {
            m_candidates.emplace_back(*index, previous_modifier);
            index = index->pprev;
        }
        m_first_height = index ? index->nHeight + 1 : 0;

        // Preserve the historical ordering procedure exactly. The shuffle is
        // consensus-neutral because the comparator fully orders distinct block
        // hashes, but retaining it avoids changing random-state side effects in
        // this structural refactor.
        for (size_t size = m_candidates.size(); size > 2; --size) {
            const size_t index{size - 1};
            std::swap(m_candidates[index], m_candidates[GetRand(index)]);
        }
        std::sort(m_candidates.begin(), m_candidates.end(), [](const auto& a, const auto& b) {
            if (a.time != b.time) return a.time < b.time;

            const uint32_t* pa = reinterpret_cast<const uint32_t*>(a.block_hash.data());
            const uint32_t* pb = reinterpret_cast<const uint32_t*>(b.block_hash.data());
            int count = 256 / 32;
            do {
                --count;
                if (pa[count] != pb[count]) return pa[count] < pb[count];
            } while (count);
            return false;
        });
    }

    const StakeModifierSelectionParams m_params;
    std::vector<StakeModifierCandidate> m_candidates;
    int m_previous_height;
    int m_first_height{0};
    int64_t m_interval_start{0};
    int64_t m_interval_stop{0};
    size_t m_selected_count{0};
};

} // namespace

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexCurrent, uint64_t &nStakeModifier, bool& fGeneratedStakeModifier, Chainstate&)
{
    const Consensus::Params& params = Params().GetConsensus();
    const CBlockIndex* pindexPrev = pindexCurrent->pprev;
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    if (gArgs.GetBoolArg("-debug", false))
        LogPrintf("ComputeNextStakeModifier: prev modifier=0x%016x time=%s epoch=%u\n", nStakeModifier, FormatISO8601DateTime(nModifierTime), (unsigned int)nModifierTime);
    if (nModifierTime / params.nModifierInterval >= pindexPrev->GetBlockTime() / params.nModifierInterval)
    {
        if (gArgs.GetBoolArg("-debug", false))
            LogPrintf("ComputeNextStakeModifier: no new interval keep current modifier: pindexPrev nHeight=%d nTime=%u\n", pindexPrev->nHeight, (unsigned int)pindexPrev->GetBlockTime());
        return true;
    }
    if (nModifierTime / params.nModifierInterval >= pindexCurrent->GetBlockTime() / params.nModifierInterval)
    {
        // v0.4+ requires current block timestamp also be in a different modifier interval
        if (IsProtocolV04(pindexCurrent->nTime))
        {
            if (gArgs.GetBoolArg("-debug", false))
                LogPrintf("ComputeNextStakeModifier: (v0.4+) no new interval keep current modifier: pindexCurrent nHeight=%d nTime=%u\n", pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
            return true;
        }
        else
        {
            if (gArgs.GetBoolArg("-debug", false))
                LogPrintf("ComputeNextStakeModifier: v0.3 modifier at block %s not meeting v0.4+ protocol: pindexCurrent nHeight=%d nTime=%u\n", pindexCurrent->GetBlockHash().ToString(), pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
        }
    }

    StakeModifierSelection selection{params, *pindexPrev, nStakeModifier};
    selection.Select();
    const uint64_t nStakeModifierNew{selection.ComputeModifier()};

    if (gArgs.GetBoolArg("-debug", false) && gArgs.GetBoolArg("-printstakemodifier", false)) {
        selection.Log();
    }
    if (gArgs.GetBoolArg("-debug", false))
        LogPrintf("ComputeNextStakeModifier: new modifier=0x%016x time=%s\n", nStakeModifierNew, FormatISO8601DateTime(pindexPrev->GetBlockTime()));

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// V0.5: Stake modifier used to hash for a stake kernel is chosen as the stake
// modifier that is (nStakeMinAge minus a selection interval) earlier than the
// stake, thus at least a selection interval later than the coin generating the
// kernel, as the generating coin is from at least nStakeMinAge ago.
static bool GetKernelStakeModifierV05(CBlockIndex* pindexPrev, unsigned int nTimeTx, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    const Consensus::Params& params = Params().GetConsensus();
    const StakeModifierSelectionParams selection_params{params};
    const CBlockIndex* pindex = pindexPrev;
    nStakeModifierHeight = pindex->nHeight;
    nStakeModifierTime = pindex->GetBlockTime();
    const int64_t nStakeModifierSelectionInterval{selection_params.interval};

    if (nStakeModifierTime + params.nStakeMinAge - nStakeModifierSelectionInterval <= (int64_t) nTimeTx)
    {
        // Best block is still more than
        // (nStakeMinAge minus a selection interval) older than kernel timestamp
        if (fPrintProofOfStake)
            return error("GetKernelStakeModifier() : best block %s at height %d too old for stake",
                pindex->GetBlockHash().ToString(), pindex->nHeight);
        else
            return false;
    }
    // loop to find the stake modifier earlier by 
    // (nStakeMinAge minus a selection interval)
    while (nStakeModifierTime + params.nStakeMinAge - nStakeModifierSelectionInterval >(int64_t) nTimeTx)
    {
        if (!pindex->pprev)
        {   // reached genesis block; should not happen
            return error("GetKernelStakeModifier() : reached genesis block");
        }
        pindex = pindex->pprev;
        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// V0.3: Stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifierV03(CBlockIndex* pindexPrev, uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake, Chainstate& chainstate)
{
    const Consensus::Params& params = Params().GetConsensus();
    const StakeModifierSelectionParams selection_params{params};
    nStakeModifier = 0;

    const CBlockIndex* pindexFrom;
    {
        LOCK(cs_main);
        pindexFrom = chainstate.m_blockman.LookupBlockIndex(hashBlockFrom);
    }

    if (!pindexFrom)
        return error("GetKernelStakeModifier() : block not indexed");

    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    const int64_t nStakeModifierSelectionInterval{selection_params.interval};


    // we need to iterate index forward but we cannot depend on chainActive.Next()
    // because there is no guarantee that we are checking blocks in active chain.
    // So, we construct a temporary chain that we will iterate over.
    // pindexFrom - this block contains coins that are used to generate PoS
    // pindexPrev - this is a block that is previous to PoS block that we are checking, you can think of it as tip of our chain
    std::vector<CBlockIndex*> tmpChain;
    int32_t nDepth = pindexPrev->nHeight - (pindexFrom->nHeight-1); // -1 is used to also include pindexFrom
    tmpChain.reserve(nDepth);
    CBlockIndex* it = pindexPrev;
    for (int i=1; i<=nDepth && !chainstate.m_chain.Contains(it); i++) {
        tmpChain.push_back(it);
        it = it->pprev;
    }
    std::reverse(tmpChain.begin(), tmpChain.end());
    size_t n = 0;

    const CBlockIndex* pindex = pindexFrom;
    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)
    {
        const CBlockIndex* old_pindex = pindex;
        pindex = nullptr;
        if (!tmpChain.empty()) {
            if (n < tmpChain.size())
                pindex = (old_pindex->nHeight >= tmpChain[0]->nHeight - 1) ? tmpChain[n++] : chainstate.m_chain.Next(old_pindex);
        } else {
            pindex = chainstate.m_chain.Next(old_pindex);
        }
        if ((!tmpChain.empty() && n >= tmpChain.size()) || pindex == NULL)
        {   // reached best block; may happen if node is behind on block chain
            if (fPrintProofOfStake || (old_pindex->GetBlockTime() + params.nStakeMinAge - nStakeModifierSelectionInterval > TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime())))
                return error("GetKernelStakeModifier() : reached best block %s at height %d from block %s",
                    old_pindex->GetBlockHash().ToString(), old_pindex->nHeight, hashBlockFrom.ToString());
            else
                return false;
        }
        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// Get the stake modifier specified by the protocol to hash for a stake kernel
static bool GetKernelStakeModifier(CBlockIndex* pindexPrev, uint256 hashBlockFrom, unsigned int nTimeTx, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake, Chainstate& chainstate)
{
    if (IsProtocolV05(nTimeTx))
    {
        bool ok = GetKernelStakeModifierV05(pindexPrev, nTimeTx, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake);
        return ok;
    }
    else
        return GetKernelStakeModifierV03(pindexPrev, hashBlockFrom, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake, chainstate);
}

// peercoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: 
//       (v0.5) uses dynamic stake modifier around 21 days before the kernel,
//              versus static stake modifier about 9 days after the staked
//              coin (txPrev) used in v0.3
//       (v0.3) scrambles computation to make it very difficult to precompute
//              future proof-of-stake at the time of the coin's confirmation
//       (v0.2) nBits (deprecated): encodes all past block timestamps
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of 
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(unsigned int nBits, CBlockIndex* pindexPrev, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTransactionRef& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake, Chainstate& chainstate)
{
    const Consensus::Params& params = Params().GetConsensus();
    const unsigned int nTimeBlockFrom{static_cast<unsigned int>(blockFrom.GetBlockTime())};
    const unsigned int nTimeTxPrev{txPrev->nTime ? txPrev->nTime : nTimeBlockFrom};
    const bool fProtocolV03{IsProtocolV03(nTimeTx)};
    const bool fProtocolV05{IsProtocolV05(nTimeTx)};

    if (nTimeTx < nTimeTxPrev)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");

    if (nTimeBlockFrom + params.nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash() : min age violation");

    if (prevout.n >= txPrev->vout.size())
        return error("CheckStakeKernelHash() : invalid kernel prevout.n");

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev->vout[prevout.n].nValue;
    // v0.3 protocol kernel hash weight starts from 0 at the 30-day min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    int64_t nTimeWeight = min((int64_t)nTimeTx - nTimeTxPrev, params.nStakeMaxAge) - (fProtocolV03 ? params.nStakeMinAge : 0);
    CBigNum bnCoinDayWeight = CBigNum(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);

    Kernel::StakeKernelHashInputs hash_inputs;
    hash_inputs.use_stake_modifier = fProtocolV03;
    hash_inputs.nBits = nBits;
    hash_inputs.nTimeBlockFrom = nTimeBlockFrom;
    hash_inputs.nTxPrevOffset = nTxPrevOffset;
    hash_inputs.nTimeTxPrev = nTimeTxPrev;
    hash_inputs.nPrevOutput = prevout.n;
    hash_inputs.nTimeTx = nTimeTx;

    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;
    if (fProtocolV03)  // v0.3 protocol
    {
        if (!GetKernelStakeModifier(pindexPrev, blockFrom.GetHash(), nTimeTx, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake, chainstate))
            return false;
        hash_inputs.nStakeModifier = nStakeModifier;
    }

    hashProofOfStake = hash_inputs.GetHash();
    if (fPrintProofOfStake)
    {
        if (fProtocolV03) {
            LOCK(cs_main);
            const CBlockIndex* pindexTmp = chainstate.m_blockman.LookupBlockIndex(blockFrom.GetHash());
            LogPrintf("CheckStakeKernelHash() : using modifier 0x%016x at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
                nStakeModifier, nStakeModifierHeight,
                FormatISO8601DateTime(nStakeModifierTime),
                pindexTmp->nHeight,
                FormatISO8601DateTime(blockFrom.GetBlockTime()));
        }
        LogPrintf("CheckStakeKernelHash() : check protocol=%s modifier=0x%016x nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            fProtocolV05 ? "0.5" : (fProtocolV03 ? "0.3" : "0.2"),
            fProtocolV03 ? nStakeModifier : (uint64_t) nBits,
            nTimeBlockFrom, nTxPrevOffset, nTimeTxPrev, prevout.n, nTimeTx,
            hashProofOfStake.ToString());
    }

    // Now check if proof-of-stake hash meets target protocol
    if (CBigNum(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay)
    {
        return false;
    }
    if (gArgs.GetBoolArg("-debug", false) && !fPrintProofOfStake)
    {
        if (fProtocolV03) {
            LOCK(cs_main);
            const CBlockIndex* pindexTmp = chainstate.m_blockman.LookupBlockIndex(blockFrom.GetHash());
            LogPrintf("CheckStakeKernelHash() : using modifier 0x%016x at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
                nStakeModifier, nStakeModifierHeight, 
                FormatISO8601DateTime(nStakeModifierTime),
                pindexTmp->nHeight,
                FormatISO8601DateTime(blockFrom.GetBlockTime()));
        }
        LogPrintf("CheckStakeKernelHash() : pass protocol=%s modifier=0x%016x nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            fProtocolV03 ? "0.3" : "0.2",
            fProtocolV03 ? nStakeModifier : (uint64_t) nBits,
            nTimeBlockFrom, nTxPrevOffset, nTimeTxPrev, prevout.n, nTimeTx,
            hashProofOfStake.ToString());
    }
    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(BlockValidationState &state, CBlockIndex* pindexPrev, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake, unsigned int nTimeTx, Chainstate& chainstate)
{
    if (!tx->IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx->GetHash().ToString());

    if (tx->vin.empty())
        return error("CheckProofOfStake() : coinstake has no inputs");

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx->vin[0];

    // Transaction index is required to get to block header
    if (!g_txindex)
        return error("CheckProofOfStake() : transaction index not available");

    // Get transaction index for the previous transaction
    uint256 block_hash_prev;
    CTransactionRef txPrev;
    if (!g_txindex->FindTx(txin.prevout.hash, block_hash_prev, txPrev))
        return error("CheckProofOfStake() : tx index not found");  // tx index not found

    // peercoin: fetch kernel block header from block index instead of disk scan
    CBlockIndex* pindexFrom{nullptr};
    {
        LOCK(cs_main);
        pindexFrom = chainstate.m_blockman.LookupBlockIndex(block_hash_prev);
    }
    if (!pindexFrom)
        return error("CheckProofOfStake() : block index not found for kernel input");
    CBlockHeader header = pindexFrom->GetBlockHeader();
    // peercoin: compute kernel offset on v31 disk layout (header + varint count + preceding txs)
    uint64_t nTxPrevOffset = 0;
    {
        CBlock blockFrom;
        if (!chainstate.m_blockman.ReadBlock(blockFrom, *pindexFrom))
            return error("CheckProofOfStake() : unable to read kernel block from disk");
        uint64_t nCount = blockFrom.vtx.size();
        size_t varint_size = nCount < 253 ? 1 : nCount <= 0xffff ? 3 : nCount <= 0xffffffff ? 5 : 9;
        nTxPrevOffset = CBlockHeader::NORMAL_SERIALIZE_SIZE + varint_size; // canonical: offset within block data, not file-absolute
        for (const auto& txo : blockFrom.vtx) {
            bool found = false;
            for (size_t o = 0; o < txo->vout.size(); ++o) {
                if (COutPoint(txo->GetHash(), o) == txin.prevout) { found = true; break; }
            }
            if (found) break;
            nTxPrevOffset += GetSerializeSize(*txo);
        }
    }

    if (txPrev->GetHash() != txin.prevout.hash)
        return error("%s() : txid mismatch in CheckProofOfStake()", __PRETTY_FUNCTION__);
    if (txin.prevout.n >= txPrev->vout.size())
        return error("CheckProofOfStake() : invalid kernel prevout.n");

    // Verify signature
    {
        int nIn = 0;
        const CTxOut& prevOut = txPrev->vout[txin.prevout.n];
        TransactionSignatureChecker checker(&(*tx), nIn, prevOut.nValue, PrecomputedTransactionData(*tx), MissingDataBehavior(1));

        if (!VerifyScript(tx->vin[nIn].scriptSig, prevOut.scriptPubKey, &(tx->vin[nIn].scriptWitness), SCRIPT_VERIFY_P2SH, checker, nullptr))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "invalid-pos-script", strprintf("%s: VerifyScript failed on coinstake %s", __func__, tx->GetHash().ToString()));
    }

    if (!CheckStakeKernelHash(nBits, pindexPrev, header, nTxPrevOffset, txPrev, txin.prevout, nTimeTx, hashProofOfStake, gArgs.GetBoolArg("-debug", false), chainstate))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "check-kernel-failed", strprintf("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx->GetHash().ToString(), hashProofOfStake.ToString())); // may occur during initial download or if behind on block chain sync

    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    if (IsProtocolV03(nTimeTx))  // v0.3 protocol
        return (nTimeBlock == nTimeTx);
    else // v0.2 protocol
        return ((nTimeTx <= nTimeBlock) && (nTimeBlock <= nTimeTx + MAX_FUTURE_BLOCK_TIME_PREV9));
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert (pindex->pprev || pindex->GetBlockHash() == Params().GetConsensus().hashGenesisBlock);
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    arith_uint256 hashChecksum = UintToArith256(Hash(ss));
    hashChecksum >>= (256 - 32);
    return hashChecksum.GetLow64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    bool fTestNet = Params().GetChainTypeString() == "test";
    if (fTestNet && mapStakeModifierTestnetCheckpoints.count(nHeight))
        return nStakeModifierChecksum == mapStakeModifierTestnetCheckpoints[nHeight];

    if (!fTestNet && mapStakeModifierCheckpoints.count(nHeight))
        return nStakeModifierChecksum == mapStakeModifierCheckpoints[nHeight];

    return true;
}

bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    return (HowSuperMajority(minVersion, pstart, nRequired, nToCheck) >= nRequired);
}

unsigned int HowSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; pstart = pstart->pprev )
    {
        if (!pstart->IsProofOfStake())
            continue;

        if (pstart->nVersion >= minVersion)
            ++nFound;

        i++;
    }
    return nFound;
}

// peercoin: entropy bit for stake modifier if chosen by modifier
unsigned int GetStakeEntropyBit(const CBlock& block)
{
    unsigned int nEntropyBit = 0;
    if (IsProtocolV04(block.nTime))
    {
        nEntropyBit = UintToArith256(block.GetHash()).GetLow64() & 1llu;// last bit of block hash
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf("GetStakeEntropyBit(v0.4+): nTime=%u hashBlock=%s entropybit=%d\n", block.nTime, block.GetHash().ToString(), nEntropyBit);
    }
    else
    {
        // old protocol for entropy bit pre v0.4
        uint160 hashSig = Hash160(block.vchBlockSig);
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf("GetStakeEntropyBit(v0.3): nTime=%u hashSig=%s", block.nTime, hashSig.ToString());
        nEntropyBit = hashSig.data()[19] >> 7;  // take the first bit of the hash
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf(" entropybit=%d\n", nEntropyBit);
    }
    return nEntropyBit;
}
