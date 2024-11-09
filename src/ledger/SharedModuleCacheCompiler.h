#pragma once
// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/SearchableBucketList.h"
#include "rust/RustBridge.h"
#include "xdrpp/types.h"

#include <cstdint>
#include <deque>

#include <condition_variable>
#include <memory>
#include <mutex>

namespace stellar
{
class Application;
class SearchableLiveBucketListSnapshot;
}

// This class encapsulates a multithreaded strategy for loading contracts
// out of the database (on one thread) and compiling them (on N-1 others).
class SharedModuleCacheCompiler
    : public std::enable_shared_from_this<SharedModuleCacheCompiler>
{
    stellar::Application& mApp;
    stellar::rust_bridge::SorobanModuleCache& mModuleCache;
    std::shared_ptr<stellar::SearchableLiveBucketListSnapshot> mSnap;
    std::deque<xdr::xvector<uint8_t>> mWasms;

    const size_t mNumThreads;
    const size_t MAX_MEM_BYTES = 10 * 1024 * 1024;
    bool mLoadedAll{false};
    size_t mBytesLoaded{0};
    size_t mBytesCompiled{0};

    std::mutex mMutex;
    std::condition_variable mHaveSpace;
    std::condition_variable mHaveContracts;

    std::chrono::microseconds mTotalCompileTime;

    void setFinishedLoading();
    bool isFinishedCompiling(std::unique_lock<std::mutex>& lock);
    // This gets called in a loop on the loader/producer thread.
    void pushWasm(xdr::xvector<uint8_t> const& vec);
    // This gets called in a loop on the compiler/consumer threads
    void popAndCompileWasm(size_t thread, std::unique_lock<std::mutex>& lock);

  public:
    SharedModuleCacheCompiler(
        stellar::Application& app,
        stellar::rust_bridge::SorobanModuleCache& moduleCache);
    void run();
};
