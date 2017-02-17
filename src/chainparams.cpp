// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf8;
        pchMessageStart[1] = 0xbc;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xd8;
        vAlertPubKey = ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        nDefaultPort = 12345;
        nRPCPort = 12344;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 28);
        nSubsidyHalvingInterval = 210000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        const char* pszTimestamp = "Blah blah blah Blah blah blah blah blah Blah blah blah blah blah Blah blah blah";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1487312892;
        genesis.nBits    = 0x1d0fffff;
        genesis.nNonce   = 249272502;

        // printf("bnProofOfWorkLimit %s : %08X \n", bnProofOfWorkLimit.ToString().c_str(), bnProofOfWorkLimit.GetCompact());
        // printf("genesis.nBits %08X \n", genesis.nBits);
        hashGenesisBlock = genesis.GetHash();
        
        // If genesis block hash does not match, then generate new genesis hash.
        uint256 tmphashGenesisBlock = uint256("0x00000009413b67a6657bf189eedb884429db5551cd45618f65073079bc04feef");
        if (true && genesis.GetHash() != tmphashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            CBigNum bnTarget;
            bnTarget.SetCompact(genesis.nBits);
            
            uint256 thash = genesis.GetPoWHash();
            
            while (thash > bnTarget.getuint256())
            {
                thash = genesis.GetPoWHash();
                if (thash <= bnTarget.getuint256())
                    break;
                if ((genesis.nNonce & 0xFFFFF) == 0)
                {
                    printf("nonce %08X: PoWhash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), bnTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            printf("genesis.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
            printf("genesis.hashMerkleRoot = %s\n", genesis.BuildMerkleTree().ToString().c_str());
        }
        
        assert(hashGenesisBlock == uint256("0x00000009413b67a6657bf189eedb884429db5551cd45618f65073079bc04feef"));
        assert(genesis.hashMerkleRoot == uint256("0xa1c37dfaac8ac852263a658ab7024bd52954a748c9b149b0aec5c3193c1c34ab"));

        vSeeds.push_back(CDNSSeedData("testcoin.local", "seed.testcoin.local"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(65);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(63);
        base58Prefixes[SECRET_KEY] =     list_of(5);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbc;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xd8;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 23456;
        nRPCPort = 23455;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1487312898;
        genesis.nNonce = 22135955;
        hashGenesisBlock = genesis.GetHash();
        
        // If genesis block hash does not match, then generate new genesis hash.
        uint256 tmphashGenesisBlock = uint256("0x0000000d346e83de7ebae57f374512525669019c6f8bbfe338b537064369ea3e");
        if (true && genesis.GetHash() != tmphashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            CBigNum bnTarget;
            bnTarget.SetCompact(genesis.nBits);
            
            uint256 thash = genesis.GetPoWHash();
            
            while (thash > bnTarget.getuint256())
            {
                thash = genesis.GetPoWHash();
                if (thash <= bnTarget.getuint256())
                    break;
                if ((genesis.nNonce & 0xFFFFF) == 0)
                {
                    printf("nonce %08X: PoWhash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), bnTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            printf("genesis.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
            printf("genesis.hashMerkleRoot = %s\n", genesis.BuildMerkleTree().ToString().c_str());
        }
        
        assert(hashGenesisBlock == uint256("0x0000000d346e83de7ebae57f374512525669019c6f8bbfe338b537064369ea3e"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testcoin.local", "test.seed.testcoin.local"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(127);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(125);
        base58Prefixes[SECRET_KEY]     = list_of(8);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xbc;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xd8;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1487312899;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
        
        // If genesis block hash does not match, then generate new genesis hash.
        uint256 tmphashGenesisBlock = uint256("0x53a40a98a383ec7cbbb3ba89d761319a0d1b3c5c604df0bd43b0137258a376a8");
        if (true && genesis.GetHash() != tmphashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            CBigNum bnTarget;
            bnTarget.SetCompact(genesis.nBits);
            
            uint256 thash = genesis.GetPoWHash();
            
            while (thash > bnTarget.getuint256())
            {
                thash = genesis.GetPoWHash();
                if (thash <= bnTarget.getuint256())
                    break;
                if ((genesis.nNonce & 0xFFFFF) == 0)
                {
                    printf("nonce %08X: PoWhash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), bnTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            printf("genesis.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
            printf("genesis.hashMerkleRoot = %s\n", genesis.BuildMerkleTree().ToString().c_str());
        }
        
        assert(hashGenesisBlock == uint256("0x53a40a98a383ec7cbbb3ba89d761319a0d1b3c5c604df0bd43b0137258a376a8"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
