// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerEntryScope.h"
#include "ledger/LedgerHashUtils.h"
#include "rust/MergedBridge.h"
#include "util/types.h"
#include "xdr/Stellar-ledger-entries.h"
#include <cstddef>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <stdexcept>

/////////////////////////////////////
// LedgerEntryScopeID
/////////////////////////////////////

namespace stellar
{
template <StaticLedgerEntryScope S>
std::ostream&
operator<<(std::ostream& os, LedgerEntryScopeID<S> const& obj)
{
    switch (S)
    {
#define STATIC_SCOPE_MACRO(SCOPE_NAME) \
    case StaticLedgerEntryScope::SCOPE_NAME: \
        os << #SCOPE_NAME; \
        break;
        FOREACH_STATIC_LEDGER_ENTRY_SCOPE(STATIC_SCOPE_MACRO)
#undef STATIC_SCOPE_MACRO
    }
    os << "[" << obj.mIndex << "]";
    if (obj.mLedger != 0)
        os << " @ Ledger " << obj.mLedger;
    return os;
}
} // namespace stellar

namespace fmt
{
template <stellar::StaticLedgerEntryScope S>
struct formatter<stellar::LedgerEntryScopeID<S>> : ostream_formatter
{
};
}

namespace stellar
{

uint16_t
clamp16(size_t v)
{
    if (v > 0xFFFF)
    {
        throw std::runtime_error(
            fmt::format("clamp16: value {} exceeds 16 bit limit", v));
    }
    return static_cast<uint16_t>(v);
}

template <StaticLedgerEntryScope S>
LedgerEntryScopeID<S>::LedgerEntryScopeID(size_t index, uint32_t ledger)
    : mIndex(clamp16(index)), mLedger(ledger)
{
}

template <StaticLedgerEntryScope S>
bool
LedgerEntryScopeID<S>::operator==(LedgerEntryScopeID<S> const& other) const
{
    return mLedger == other.mLedger && mIndex == other.mIndex;
}

template <StaticLedgerEntryScope S>
bool
LedgerEntryScopeID<S>::operator!=(LedgerEntryScopeID<S> const& other) const
{
    return !(*this == other);
}

/////////////////////////////////////
// ScopedLedgerEntry
/////////////////////////////////////

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>::ScopedLedgerEntry(ScopeIdT scopeID,
                                        LedgerEntry const& entry)
    : mEntry(entry), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>::ScopedLedgerEntry(ScopeIdT scopeID, LedgerEntry&& entry)
    : mEntry(std::move(entry)), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>::ScopedLedgerEntry(ScopedLedgerEntry<S> const& other)
    : mEntry(other.mEntry), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>::ScopedLedgerEntry(ScopedLedgerEntry<S>&& other)
    : mEntry(std::move(other.mEntry)), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>&
ScopedLedgerEntry<S>::operator=(ScopedLedgerEntry<S> const& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator=: scope ID '{}' != entry scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    mEntry = other.mEntry;
    return *this;
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>&
ScopedLedgerEntry<S>::operator=(ScopedLedgerEntry<S>&& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(
            fmt::format("move operator=: scope ID '{}' != entry scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    mEntry = std::move(other.mEntry);
    return *this;
}

template <StaticLedgerEntryScope S>
LedgerEntry const&
ScopedLedgerEntry<S>::readInScope(LedgerEntryScope<S> const& scope) const
{
    return scope.scopeReadEntry(*this);
}

template <StaticLedgerEntryScope S>
void
ScopedLedgerEntry<S>::modifyInScope(LedgerEntryScope<S> const& scope,
                                    std::function<void(LedgerEntry&)> func)
{
    scope.scopeModifyEntry(*this, func);
}

template <StaticLedgerEntryScope S>
bool
ScopedLedgerEntry<S>::operator==(ScopedLedgerEntry<S> const& other) const
{
    if (mScopeID != other.mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator==: scope ID '{}' != other scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    return mEntry == other.mEntry;
}

template <StaticLedgerEntryScope S>
bool
ScopedLedgerEntry<S>::operator<(ScopedLedgerEntry<S> const& other) const
{
    if (mScopeID != other.mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator<: scope ID '{}' != other scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    return mEntry < other.mEntry;
}

/////////////////////////////////////
// ScopedLedgerEntryOpt
/////////////////////////////////////

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(
    ScopeIdT scopeID, std::optional<LedgerEntry> const& entry)
    : mEntry(entry), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(
    ScopeIdT scopeID, std::optional<LedgerEntry>&& entry)
    : mEntry(std::move(entry)), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(
    ScopedLedgerEntryOpt<S> const& other)
    : mEntry(other.mEntry), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(ScopedLedgerEntryOpt<S>&& other)
    : mEntry(std::move(other.mEntry)), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(ScopedLedgerEntry<S> const& other)
    : mEntry(other.mEntry), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>::ScopedLedgerEntryOpt(ScopedLedgerEntry<S>&& other)
    : mEntry(std::move(other.mEntry)), mScopeID(other.mScopeID)
{
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>&
ScopedLedgerEntryOpt<S>::operator=(ScopedLedgerEntryOpt<S> const& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator=: scope ID '{}' != entry scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    mEntry = other.mEntry;
    return *this;
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>&
ScopedLedgerEntryOpt<S>::operator=(ScopedLedgerEntryOpt<S>&& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(
            fmt::format("move operator=: scope ID '{}' != entry scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    mEntry = std::move(other.mEntry);
    return *this;
}

template <StaticLedgerEntryScope S>
std::optional<LedgerEntry> const&
ScopedLedgerEntryOpt<S>::readInScope(LedgerEntryScope<S> const& scope) const
{
    return scope.scopeReadOptionalEntry(*this);
}

template <StaticLedgerEntryScope S>
void
ScopedLedgerEntryOpt<S>::modifyInScope(
    LedgerEntryScope<S> const& scope,
    std::function<void(std::optional<LedgerEntry>&)> func)
{
    scope.scopeModifyOptionalEntry(*this, func);
}

template <StaticLedgerEntryScope S>
bool
ScopedLedgerEntryOpt<S>::operator==(ScopedLedgerEntryOpt<S> const& other) const
{
    if (mScopeID != other.mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator==: scope ID '{}' != other scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    return mEntry == other.mEntry;
}

template <StaticLedgerEntryScope S>
bool
ScopedLedgerEntryOpt<S>::operator<(ScopedLedgerEntryOpt<S> const& other) const
{
    if (mScopeID != other.mScopeID)
    {
        throw std::runtime_error(
            fmt::format("operator<: scope ID '{}' != other scope ID '{}'",
                        mScopeID, other.mScopeID));
    }
    return mEntry < other.mEntry;
}

/////////////////////////////////////
// LedgerEntryScope
/////////////////////////////////////

template <StaticLedgerEntryScope S>
LedgerEntryScope<S>::LedgerEntryScope(LedgerEntryScopeID<S> scopeID)
    : mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
void
LedgerEntryScope<S>::scopeActivate() const
{
    if (mActive)
    {
        throw std::runtime_error(fmt::format(
            "LedgerEntryScope::scopeActivate: scope {} already active",
            mScopeID));
    }
    mActive = true;
}

template <StaticLedgerEntryScope S>
void
LedgerEntryScope<S>::scopeDeactivate() const
{
    if (!mActive)
    {
        throw std::runtime_error(fmt::format(
            "LedgerEntryScope::scopeDeactivate: scope {} already inactive",
            mScopeID));
    }
    mActive = false;
}

template <StaticLedgerEntryScope S>
LedgerEntry const&
LedgerEntryScope<S>::scopeReadEntry(ScopedLedgerEntry<S> const& w) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(
            fmt::format("scopeReadEntry: scope ID '{}' != entry scope ID '{}'",
                        mScopeID, w.mScopeID));
    }
    return w.mEntry;
}

template <StaticLedgerEntryScope S>
void
LedgerEntryScope<S>::scopeModifyEntry(
    ScopedLedgerEntry<S>& w, std::function<void(LedgerEntry&)> func) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "scopeModifyEntry: scope ID '{}' != entry scope ID '{}'", mScopeID,
            w.mScopeID));
    }
    func(w.mEntry);
}

template <StaticLedgerEntryScope S>
std::optional<LedgerEntry> const&
LedgerEntryScope<S>::scopeReadOptionalEntry(
    ScopedLedgerEntryOpt<S> const& w) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "scopeReadOptionalEntry: scope ID '{}' != entry scope ID '{}'",
            mScopeID, w.mScopeID));
    }
    return w.mEntry;
}

template <StaticLedgerEntryScope S>
void
LedgerEntryScope<S>::scopeModifyOptionalEntry(
    ScopedLedgerEntryOpt<S>& w,
    std::function<void(std::optional<LedgerEntry>&)> func) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "scopeModifyOptionalEntry: scope ID '{}' != entry scope ID '{}'",
            mScopeID, w.mScopeID));
    }
    func(w.mEntry);
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>
LedgerEntryScope<S>::scopeAdoptEntry(LedgerEntry&& entry) const
{
    return ScopedLedgerEntry(mScopeID, std::move(entry));
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntry<S>
LedgerEntryScope<S>::scopeAdoptEntry(LedgerEntry const& entry) const
{
    return ScopedLedgerEntry(mScopeID, entry);
}

template <StaticLedgerEntryScope S>
ScopedLedgerEntryOpt<S>
LedgerEntryScope<S>::scopeAdoptEntryOpt(
    std::optional<LedgerEntry> const& entry) const
{
    return ScopedLedgerEntryOpt(mScopeID, entry);
}

template <StaticLedgerEntryScope S>
template <StaticLedgerEntryScope OtherScope>
ScopedLedgerEntry<S>
LedgerEntryScope<S>::scopeAdoptEntryFromImpl(
    ScopedLedgerEntry<OtherScope> const& entry,
    LedgerEntryScope<OtherScope> const& scope) const
{
    // NB: Here we do _not_ do a `scopeReadEntry` on the adopting-from scope.
    // Quite the opposite! We check that the adopting-from scope is _inactive_
    // so that it's correct for us to be adopting the entry without introducing
    // risk of read inconsistency.
    if (scope.mActive)
    {
        throw std::runtime_error(fmt::format(
            "scopeAdoptEntryFrom: adopting entry with scope ID {} from "
            "still-active scope ID '{}'",
            entry.mScopeID, scope.mScopeID));
    }
    return EntryT{mScopeID, entry.mEntry};
}

template <StaticLedgerEntryScope S>
template <StaticLedgerEntryScope OtherScope>
ScopedLedgerEntryOpt<S>
LedgerEntryScope<S>::scopeAdoptEntryOptFromImpl(
    ScopedLedgerEntryOpt<OtherScope> const& entry,
    LedgerEntryScope<OtherScope> const& scope) const
{
    if (scope.mActive)
    {
        throw std::runtime_error(
            fmt::format("scopeAdoptEntryOptFrom: adopting entry with "
                        "scope ID {} from "
                        "still-active scope ID '{}'",
                        entry.mScopeID, scope.mScopeID));
    }
    return ScopedLedgerEntryOpt<S>{mScopeID, entry.mEntry};
}

/////////////////////////////////
// DeactivateScopeGuard
/////////////////////////////////

template <StaticLedgerEntryScope S>
DeactivateScopeGuard<S>::DeactivateScopeGuard(LedgerEntryScope<S> const& scope)
    : mScope(scope)
{
    mScope.scopeDeactivate();
}
template <StaticLedgerEntryScope S>
DeactivateScopeGuard<S>::~DeactivateScopeGuard()
{
    mScope.scopeActivate();
}

/////////////////////////////////////
// LazyScopedLedgerEntry
/////////////////////////////////////

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntry<S>::LazyScopedLedgerEntry(
    ScopeIdT scopeID,
    rust::Box<stellar::lazy_xdr::LazyLedgerEntry> entry)
    : mEntry(std::move(entry)), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntry<S>&
LazyScopedLedgerEntry<S>::operator=(LazyScopedLedgerEntry<S>&& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "LazyScopedLedgerEntry move operator=: scope ID '{}' != entry "
            "scope ID '{}'",
            mScopeID, other.mScopeID));
    }
    mEntry = std::move(other.mEntry);
    return *this;
}

template <StaticLedgerEntryScope S>
stellar::lazy_xdr::LazyLedgerEntry const&
LazyScopedLedgerEntry<S>::readInScope(LedgerEntryScope<S> const& scope) const
{
    return scope.scopeReadLazyEntry(*this);
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntry<S>
LazyScopedLedgerEntry<S>::clone() const
{
    return LazyScopedLedgerEntry(
        mScopeID, stellar::lazy_xdr::lazy_ledger_entry_clone(*mEntry));
}

/////////////////////////////////////
// LazyScopedLedgerEntryOpt
/////////////////////////////////////

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntryOpt<S>::LazyScopedLedgerEntryOpt(
    ScopeIdT scopeID,
    std::unique_ptr<rust::Box<stellar::lazy_xdr::LazyLedgerEntry>> entry)
    : mEntry(std::move(entry)), mScopeID(scopeID)
{
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntryOpt<S>&
LazyScopedLedgerEntryOpt<S>::operator=(LazyScopedLedgerEntryOpt<S>&& other)
{
    if (this == &other)
    {
        return *this;
    }
    if (other.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "LazyScopedLedgerEntryOpt move operator=: scope ID '{}' != entry "
            "scope ID '{}'",
            mScopeID, other.mScopeID));
    }
    mEntry = std::move(other.mEntry);
    return *this;
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntryOpt<S>::LazyScopedLedgerEntryOpt(
    LazyScopedLedgerEntry<S>&& entry)
    : mEntry(std::make_unique<rust::Box<stellar::lazy_xdr::LazyLedgerEntry>>(
          std::move(entry.mEntry)))
    , mScopeID(entry.mScopeID)
{
}

template <StaticLedgerEntryScope S>
bool
LazyScopedLedgerEntryOpt<S>::hasValue() const
{
    return mEntry != nullptr;
}

template <StaticLedgerEntryScope S>
stellar::lazy_xdr::LazyLedgerEntry const&
LazyScopedLedgerEntryOpt<S>::readInScope(
    LedgerEntryScope<S> const& scope) const
{
    auto const* ptr = scope.scopeReadLazyOptionalEntry(*this);
    if (!ptr)
    {
        throw std::runtime_error(
            "LazyScopedLedgerEntryOpt::readInScope: entry is empty");
    }
    return *ptr;
}

template <StaticLedgerEntryScope S>
stellar::lazy_xdr::LazyLedgerEntry const*
LazyScopedLedgerEntryOpt<S>::readOptInScope(
    LedgerEntryScope<S> const& scope) const
{
    return scope.scopeReadLazyOptionalEntry(*this);
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntryOpt<S>
LazyScopedLedgerEntryOpt<S>::clone() const
{
    if (mEntry)
    {
        return LazyScopedLedgerEntryOpt(
            mScopeID,
            std::make_unique<rust::Box<stellar::lazy_xdr::LazyLedgerEntry>>(
                stellar::lazy_xdr::lazy_ledger_entry_clone(**mEntry)));
    }
    return LazyScopedLedgerEntryOpt(
        mScopeID,
        std::unique_ptr<rust::Box<stellar::lazy_xdr::LazyLedgerEntry>>());
}

/////////////////////////////////////
// LedgerEntryScope lazy methods
/////////////////////////////////////

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntry<S>
LedgerEntryScope<S>::scopeAdoptLazyEntry(
    rust::Box<stellar::lazy_xdr::LazyLedgerEntry> entry) const
{
    return LazyScopedLedgerEntry<S>{mScopeID, std::move(entry)};
}

template <StaticLedgerEntryScope S>
LazyScopedLedgerEntryOpt<S>
LedgerEntryScope<S>::scopeAdoptLazyEntryOpt(
    std::unique_ptr<rust::Box<stellar::lazy_xdr::LazyLedgerEntry>> entry) const
{
    return LazyScopedLedgerEntryOpt<S>{mScopeID, std::move(entry)};
}

template <StaticLedgerEntryScope S>
stellar::lazy_xdr::LazyLedgerEntry const&
LedgerEntryScope<S>::scopeReadLazyEntry(
    LazyScopedLedgerEntry<S> const& w) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "scopeReadLazyEntry: scope ID '{}' != entry scope ID '{}'",
            mScopeID, w.mScopeID));
    }
    return *w.mEntry;
}

template <StaticLedgerEntryScope S>
stellar::lazy_xdr::LazyLedgerEntry const*
LedgerEntryScope<S>::scopeReadLazyOptionalEntry(
    LazyScopedLedgerEntryOpt<S> const& w) const
{
    if (w.mScopeID != mScopeID)
    {
        throw std::runtime_error(fmt::format(
            "scopeReadLazyOptionalEntry: scope ID '{}' != entry scope ID '{}'",
            mScopeID, w.mScopeID));
    }
    if (w.mEntry)
    {
        return &(**w.mEntry);
    }
    return nullptr;
}

template <StaticLedgerEntryScope S>
template <StaticLedgerEntryScope OtherScope>
LazyScopedLedgerEntry<S>
LedgerEntryScope<S>::scopeAdoptLazyEntryFromImpl(
    LazyScopedLedgerEntry<OtherScope>&& entry,
    LedgerEntryScope<OtherScope> const& scope) const
{
    if (scope.mActive)
    {
        throw std::runtime_error(fmt::format(
            "scopeAdoptLazyEntryFrom: adopting entry with scope ID {} from "
            "still-active scope ID '{}'",
            entry.mScopeID, scope.mScopeID));
    }
    return LazyScopedLedgerEntry<S>{mScopeID, std::move(entry.mEntry)};
}

template <StaticLedgerEntryScope S>
template <StaticLedgerEntryScope OtherScope>
LazyScopedLedgerEntryOpt<S>
LedgerEntryScope<S>::scopeAdoptLazyEntryOptFromImpl(
    LazyScopedLedgerEntryOpt<OtherScope>&& entry,
    LedgerEntryScope<OtherScope> const& scope) const
{
    if (scope.mActive)
    {
        throw std::runtime_error(fmt::format(
            "scopeAdoptLazyEntryOptFrom: adopting entry with scope ID {} from "
            "still-active scope ID '{}'",
            entry.mScopeID, scope.mScopeID));
    }
    return LazyScopedLedgerEntryOpt<S>{mScopeID, std::move(entry.mEntry)};
}

#define INSTANTIATE_SCOPE_CLASSES(SCOPE_NAME) \
    template class LedgerEntryScopeID<StaticLedgerEntryScope::SCOPE_NAME>; \
    template class LedgerEntryScope<StaticLedgerEntryScope::SCOPE_NAME>; \
    template class ScopedLedgerEntry<StaticLedgerEntryScope::SCOPE_NAME>; \
    template class ScopedLedgerEntryOpt<StaticLedgerEntryScope::SCOPE_NAME>; \
    template class DeactivateScopeGuard<StaticLedgerEntryScope::SCOPE_NAME>; \
    template class LazyScopedLedgerEntry< \
        StaticLedgerEntryScope::SCOPE_NAME>; \
    template class LazyScopedLedgerEntryOpt< \
        StaticLedgerEntryScope::SCOPE_NAME>;

FOREACH_STATIC_LEDGER_ENTRY_SCOPE(INSTANTIATE_SCOPE_CLASSES)
#undef INSTANTIATE_SCOPE_CLASSES

#define INSTANTIATE_ADOPT_METHODS(DEST_SCOPE, SOURCE_SCOPE) \
    template ScopedLedgerEntry<StaticLedgerEntryScope::DEST_SCOPE> \
    LedgerEntryScope<StaticLedgerEntryScope::DEST_SCOPE>:: \
        scopeAdoptEntryFromImpl<StaticLedgerEntryScope::SOURCE_SCOPE>( \
            ScopedLedgerEntry<StaticLedgerEntryScope::SOURCE_SCOPE> const&, \
            LedgerEntryScope<StaticLedgerEntryScope::SOURCE_SCOPE> const&) \
            const; \
\
    template ScopedLedgerEntryOpt<StaticLedgerEntryScope::DEST_SCOPE> \
    LedgerEntryScope<StaticLedgerEntryScope::DEST_SCOPE>:: \
        scopeAdoptEntryOptFromImpl<StaticLedgerEntryScope::SOURCE_SCOPE>( \
            ScopedLedgerEntryOpt<StaticLedgerEntryScope::SOURCE_SCOPE> const&, \
            LedgerEntryScope<StaticLedgerEntryScope::SOURCE_SCOPE> const&) \
            const; \
\
    template LazyScopedLedgerEntry<StaticLedgerEntryScope::DEST_SCOPE> \
    LedgerEntryScope<StaticLedgerEntryScope::DEST_SCOPE>:: \
        scopeAdoptLazyEntryFromImpl<StaticLedgerEntryScope::SOURCE_SCOPE>( \
            LazyScopedLedgerEntry<StaticLedgerEntryScope::SOURCE_SCOPE>&&, \
            LedgerEntryScope<StaticLedgerEntryScope::SOURCE_SCOPE> const&) \
            const; \
\
    template LazyScopedLedgerEntryOpt<StaticLedgerEntryScope::DEST_SCOPE> \
    LedgerEntryScope<StaticLedgerEntryScope::DEST_SCOPE>:: \
        scopeAdoptLazyEntryOptFromImpl<StaticLedgerEntryScope::SOURCE_SCOPE>( \
            LazyScopedLedgerEntryOpt< \
                StaticLedgerEntryScope::SOURCE_SCOPE>&&, \
            LedgerEntryScope<StaticLedgerEntryScope::SOURCE_SCOPE> const&) \
            const;

FOR_EACH_VALID_SCOPE_ADOPTION(INSTANTIATE_ADOPT_METHODS)
#undef INSTANTIATE_ADOPT_METHODS

}
