// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <sodium.h>

#include "crypto/Random.h"
#include "crypto/ShortHash.h"
#include "ledger/test/LedgerTestUtils.h"
#include "lib/catch.hpp"
#include "lib/util/siphash.h"
#include <autocheck/generator.hpp>

// Confirms that the incremental implementation in siphash.h
// behaves the same as the reference implementation in sodium.

using namespace stellar;

TEST_CASE("siphash", "[siphash]")
{
    CHECK(16 == crypto_shorthash_KEYBYTES);
    for (size_t i = 0; i < 1000; ++i)
    {
        std::vector<uint8_t> input = randomBytes(5 + (i * 10));
        unsigned char key[crypto_shorthash_KEYBYTES];
        crypto_shorthash_keygen(key);
        uint64_t sodium_sip;
        crypto_shorthash(reinterpret_cast<unsigned char*>(&sodium_sip),
                         reinterpret_cast<const unsigned char*>(input.data()),
                         input.size(), key);
        SipHash sip(key);
        sip.update(input.data(), input.size());
        CHECK(sodium_sip == sip.digest());
    }
}

TEST_CASE("xdr siphash", "[siphash]")
{
    for (size_t i = 0; i < 1000; ++i)
    {
        auto entry = LedgerTestUtils::generateValidLedgerEntry(100);
        auto bytes_hash =
            shortHash::computeHash(xdr::xdr_to_opaque(entry));
        auto stream_hash = shortHash::computeXDRHash(entry);
        CHECK(bytes_hash == stream_hash);
    }
}

TEST_CASE("shorthash libsodium bytes bench", "[!hide][sh-sodium-bytes-bench]")
{
    shortHash::initialize();
    autocheck::rng().seed(11111);
    std::vector<LedgerEntry> entries;
    for (size_t i = 0; i < 1000; ++i)
    {
        entries.emplace_back(LedgerTestUtils::generateValidLedgerEntry(1000));
    }
    unsigned char key[crypto_shorthash_KEYBYTES];
    crypto_shorthash_keygen(key);
    for (size_t i = 0; i < 10000; ++i)
    {
        for (auto const& e : entries)
        {
            auto opaque = xdr::xdr_to_opaque(e);
            uint64_t sodium_sip;
            crypto_shorthash(reinterpret_cast<unsigned char*>(&sodium_sip),
                             reinterpret_cast<const unsigned char*>(opaque.data()),
                             opaque.size(), key);
        }
    }
}

TEST_CASE("shorthash SipHash bytes bench", "[!hide][sh-bytes-bench]")
{
    shortHash::initialize();
    autocheck::rng().seed(11111);
    std::vector<LedgerEntry> entries;
    for (size_t i = 0; i < 1000; ++i)
    {
        entries.emplace_back(LedgerTestUtils::generateValidLedgerEntry(1000));
    }
    unsigned char key[crypto_shorthash_KEYBYTES];
    crypto_shorthash_keygen(key);
    for (size_t i = 0; i < 10000; ++i)
    {
        for (auto const& e : entries)
        {
            auto opaque = xdr::xdr_to_opaque(e);
            SipHash h(key);
            h.update(opaque.data(), opaque.size());
            (void)h.digest();
        }
    }
}

TEST_CASE("shorthash SipHash XDR bench", "[!hide][sh-xdr-bench]")
{
    shortHash::initialize();
    autocheck::rng().seed(11111);
    std::vector<LedgerEntry> entries;
    for (size_t i = 0; i < 1000; ++i)
    {
        entries.emplace_back(LedgerTestUtils::generateValidLedgerEntry(1000));
    }
    unsigned char key[crypto_shorthash_KEYBYTES];
    crypto_shorthash_keygen(key);
    for (size_t i = 0; i < 10000; ++i)
    {
        for (auto const& e : entries)
        {
            shortHash::computeXDRHash(e);
        }
    }
}

