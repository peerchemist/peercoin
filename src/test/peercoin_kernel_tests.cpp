// Copyright (c) 2026 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(peercoin_kernel_tests)

BOOST_AUTO_TEST_CASE(stake_kernel_hash_inputs)
{
    Kernel::StakeKernelHashInputs inputs;
    inputs.nBits = 0x1d00ffff;
    inputs.nStakeModifier = 0x0123456789abcdef;
    inputs.nTimeBlockFrom = 1345083810;
    inputs.nTxPrevOffset = 81;
    inputs.nTimeTxPrev = 1345083811;
    inputs.nPrevOutput = 2;
    inputs.nTimeTx = 1345084000;

    inputs.use_stake_modifier = false;
    BOOST_CHECK_EQUAL(inputs.GetHash().GetHex(), "def5d5f23e4e056de312044a9ff6e58ba48102e78dd0341ee64c0b07a338c00c");

    inputs.use_stake_modifier = true;
    BOOST_CHECK_EQUAL(inputs.GetHash().GetHex(), "0a0fd531f2108cd00ff595039afc1b0b77dba6a35bb016908f598070e58e2fe7");
}

BOOST_AUTO_TEST_SUITE_END()
