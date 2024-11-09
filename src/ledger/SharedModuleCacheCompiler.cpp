#include "ledger/SharedModuleCacheCompiler.h"
#include "crypto/Hex.h"
#include "main/Application.h"
#include "rust/RustBridge.h"
#include "util/Logging.h"
#include <ratio>

using namespace stellar;

SharedModuleCacheCompiler::SharedModuleCacheCompiler(
    Application& app, rust_bridge::SorobanModuleCache& moduleCache)
    : mApp(app)
    , mModuleCache(moduleCache)
    , mSnap(app.getBucketManager().getSearchableLiveBucketListSnapshot())
    , mNumThreads(
          static_cast<size_t>(std::max(2, app.getConfig().WORKER_THREADS) - 1))
{
}

void
SharedModuleCacheCompiler::pushWasm(xdr::xvector<uint8_t> const& vec)
{
    std::unique_lock<std::mutex> lock(mMutex);
    mHaveSpace.wait(
        lock, [&] { return mBytesLoaded - mBytesCompiled < MAX_MEM_BYTES; });
    xdr::xvector<uint8_t> buf(vec);
    auto size = buf.size();
    mWasms.emplace_back(std::move(buf));
    mBytesLoaded += size;
    lock.unlock();
    mHaveContracts.notify_all();
    LOG_INFO(DEFAULT_LOG, "Loaded contract with {} bytes of wasm code", size);
}

bool
SharedModuleCacheCompiler::isFinishedCompiling(
    std::unique_lock<std::mutex>& lock)
{
    releaseAssert(lock.owns_lock());
    return mLoadedAll && mBytesCompiled == mBytesLoaded;
}

void
SharedModuleCacheCompiler::setFinishedLoading()
{
    std::unique_lock lock(mMutex);
    mLoadedAll = true;
    lock.unlock();
    mHaveContracts.notify_all();
}

void
SharedModuleCacheCompiler::popAndCompileWasm(size_t thread,
                                             std::unique_lock<std::mutex>& lock)
{

    releaseAssert(lock.owns_lock());

    // Wait for a new contract to compile (or being done).
    mHaveContracts.wait(
        lock, [&] { return !mWasms.empty() || isFinishedCompiling(lock); });

    // Check to see if we were woken up due to end-of-compilation.
    if (isFinishedCompiling(lock))
    {
        return;
    }

    xdr::xvector<uint8_t> wasm = std::move(mWasms.front());
    mWasms.pop_front();

    // Make a local shallow copy of the cache, so we don't race on the
    // shared host.
    auto cache = mModuleCache.shallow_clone();

    lock.unlock();

    auto start = std::chrono::steady_clock::now();
    auto slice = rust::Slice<const uint8_t>(wasm.data(), wasm.size());
    try
    {
        cache->compile(slice);
    }
    catch (std::exception const& e)
    {
        LOG_ERROR(DEFAULT_LOG, "Thread {} failed to compile wasm code: {}",
                  thread, e.what());
    }
    auto end = std::chrono::steady_clock::now();
    auto dur_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    LOG_INFO(DEFAULT_LOG, "Thread {} compiled {} byte wasm contract {} in {}us",
             thread, wasm.size(), binToHex(sha256(wasm)), dur_us.count());
    lock.lock();
    mTotalCompileTime += dur_us;
    mBytesCompiled += wasm.size();
    wasm.clear();
    mHaveSpace.notify_all();
    mHaveContracts.notify_all();
}

void
SharedModuleCacheCompiler::run()
{
    auto self = shared_from_this();
    auto start = std::chrono::steady_clock::now();
    LOG_INFO(DEFAULT_LOG,
             "Launching 1 loading and {} compiling background threads",
             mNumThreads);
    mApp.postOnBackgroundThread(
        [self]() {
            self->mSnap->scanForContractCode([&](LedgerEntry const& entry) {
                self->pushWasm(entry.data.contractCode().code);
                return Loop::INCOMPLETE;
            });
            self->setFinishedLoading();
        },
        "contract loading thread");

    for (auto thread = 0; thread < self->mNumThreads; ++thread)
    {
        mApp.postOnBackgroundThread(
            [self, thread]() {
                size_t nContractsCompiled = 0;
                std::unique_lock<std::mutex> lock(self->mMutex);
                while (!self->isFinishedCompiling(lock))
                {
                    self->popAndCompileWasm(thread, lock);
                    ++nContractsCompiled;
                }
                LOG_INFO(DEFAULT_LOG, "Thread {} compiled {} contracts", thread,
                         nContractsCompiled);
            },
            fmt::format("compilation thread {}", thread));
    }

    std::unique_lock lock(self->mMutex);
    self->mHaveContracts.wait(
        lock, [self, &lock] { return self->isFinishedCompiling(lock); });

    auto end = std::chrono::steady_clock::now();
    LOG_INFO(DEFAULT_LOG,
             "All contracts compiled in {}us real time, {}us CPU time",
             std::chrono::duration_cast<std::chrono::microseconds>(end - start)
                 .count(),
             self->mTotalCompileTime.count());
}
