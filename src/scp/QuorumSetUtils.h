// Copyright 2016 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "util/BitSetCpp.h"
#include "util/HashOfHash.h"
#include "xdr/Stellar-SCP.h"

#include <unordered_map>
#include <vector>

namespace stellar
{

bool isQuorumSetSane(SCPQuorumSet const& qSet, bool extraChecks);

// normalize the quorum set, optionally removing idToRemove
void normalizeQSet(SCPQuorumSet& qSet, NodeID const* idToRemove = nullptr);

// Utility class that performs calculations on qsets using bitsets.
class QSetCalculator
{
    std::unordered_map<NodeID, size_t> mNodeNumbers;
    std::unordered_map<Hash, size_t> mQSetNumbers;
    std::vector<BitSet> mNodeQSets;
    std::vector<BitSet> mQSetNodes;
    std::vector<BitSet> mQSetNodeTransitiveClosures;
    BitSet mDirtyNodesInTransitiveClosures;

    void addQSetNodesToBitSet(BitSet &bitSet, SCPQuorumSet const& qSet);
    void recomputeDirtyTransitiveClosures();
    void computeQSetTransitiveClosure(BitSet &tcNodes, size_t qSet);

    size_t getNodeNumber(NodeID node);
    size_t getQSetNumber(Hash qSetHash);
    BitSet& getNodeQSets(size_t node);
    BitSet& getQSetNodes(size_t qset);
    BitSet& getQSetNodeTransitiveClosures(size_t qser);

public:

    // Add a qset to the calculator, indexing its nodes and calculating
    // its transitive closure eagerly.
    void addQSet(SCPQuorumSet const& qSet);

    // Add the fact that `node` trusts `qSetHash` to the calculator,
    // invalidating any transitive closures that involve `node`.
    void addQSetForNode(NodeID node, Hash qSetHash);

    // Recalculate any dirty transitive closures and query transitive
    // closure of the given `qSetHash` for the presence of `node`.
    bool isNodeInQSetTransitiveClosure(NodeID node, Hash qSetHash);
};

}
