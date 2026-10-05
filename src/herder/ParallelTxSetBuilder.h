// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/SurgePricingUtils.h"
#include "herder/TxSetFrame.h"
#include "ledger/NetworkConfig.h"
#include "main/Config.h"

namespace stellar
{
struct ParallelSorobanPhaseMetrics
{
    size_t mTxCount{0};
    size_t mStageCount{0};
    size_t mUniqueFootprintKeyCount{0};
    size_t mReadWriteFootprintKeyCount{0};
    size_t mContendedFootprintKeyCount{0};
    size_t mContractInstanceCount{0};
    std::vector<size_t> mStageTxCounts;
    std::vector<uint64_t> mStageInstructionCounts;
    std::vector<size_t> mStageConflictingTxCounts;
    std::vector<uint64_t> mStageMaxClusterInstructionCounts;
    std::vector<size_t> mStageMaxDependencyComponentTxCounts;
    std::vector<uint64_t> mStageMaxDependencyComponentInstructionCounts;
    std::vector<size_t> mClusterCounts;
    std::vector<size_t> mClusterTxCounts;
    std::vector<uint64_t> mClusterInstructionCounts;
    std::vector<size_t> mDependencyComponentCounts;
    std::vector<size_t> mDependencyComponentTxCounts;
};

// Analyzes the shape and footprint contention of a canonical parallel Soroban
// phase. Dependency components use the same conflict relation as the builder.
ParallelSorobanPhaseMetrics
analyzeParallelSorobanPhase(TxStageFrameList const& stages);

// Builds a sequence of parallel processing stages from the provided
// transactions while respecting the limits defined by the network
// configuration.
// The number of stages and the number of clusters in each stage is determined
// by the provided configurations (`cfg` and `sorobanCfg`).
// The resource limits in transactions are determined based on the input
// `laneConfig`.
// This doesn't support multi-lane surge pricing and thus it's expected
// `laneConfig` to only have a configuration for a single surge pricing lane.
TxStageFrameList buildSurgePricedParallelSorobanPhase(
    TxFrameList const& txFrames, Config const& cfg,
    SorobanNetworkConfig const& sorobanCfg,
    std::shared_ptr<SurgePricingLaneConfig> laneConfig,
    std::vector<bool>& hadTxNotFittingLane, uint32_t ledgerVersion);

} // namespace stellar
