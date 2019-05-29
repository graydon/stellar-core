// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "QuorumIntersectionChecker.h"

#include "main/Config.h"
#include "util/BitSet.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "xdr/Stellar-SCP.h"
#include "xdr/Stellar-types.h"

#include <unordered_map>

////////////////////////////////////////////////////////////////////////////////
// Quorum intersection checking
////////////////////////////////////////////////////////////////////////////////
//
// Algorithm thanks to Łukasz Lachowski <l.lachowski@gmail.com>, code largely
// derived from his implementation (Copyright 2018, MIT licensed).
//
//   See https://arxiv.org/pdf/1902.06493.pdf
//   and https://github.com/fixxxedpoint/quorum_intersection.git
//
// There's a fair bit of ground to cover in understanding what this algorithm is
// doing and convincing you, reader, that it's correct (as I had to convince
// myself). I've therefore (re)written it in as plain and explicit (and maybe
// over-verbose) a style as possible, to be as expository and convincing, as
// well as including this gruesomely long comment to guide you in
// reading. Please don't add anything clever unless you've got a very good
// performance reason, and even then make sure you add docs explaining what
// you've done.
//
//
// Definitions
// ===========
//
// - A network N is a set of nodes {N₀, N₁, ...}
//
// - Every node Nᵢ has an associated quorum qet (or "qset") QSᵢ that is a set of
//   subsets of N.
//
// - Every element of a qset QSᵢ is called a quorum slice.
//
// - A quorum Q ⊆ N is a set satisfying: Q ≠ ∅ and Ɐ v ∈ Q, ∃ S ∈ QSᵢ, S ⊆ Q
//
// - Equivalently in english: a quorum is a subset of the network such that for
//   each node Nᵢ in the quorum, there's some slice S in the node's quorum set
//   QSᵢ that is itself (S) also a subset of the quorum. In this case we also
//   say the quorum "contains a slice for Nᵢ" or "satisfies QSᵢ" or "satisfies
//   Nᵢ". Note that this definition is not always satisfiable: many networks have
//   no quorums.
//
// - A network N "enjoys quorum intersection" if every pair of quorums intersects
//   in at least a single node.
//
// - A minimal quorum (or min-quorum or minq) is a quorum that does not have any
//   quorum as a proper subset.
//
// - A network N and its quorum sets induce a directed graph Gₙ, in which the
//   vertices are the nodes of the network and an edge exists between any node
//   Nᵢ and Nⱼ when Nⱼ is in one of the quorum slices in QSᵢ. In other words,
//   the graph has an edge for every dependency between a node and a member
//   of one of its quorum slices.
//
// - A strongly connected component is a subset C of a network in which every
//   pair of nodes Nᵢ and Nⱼ ∈ C can reach each other by following edges Gₙ.
//
//
// Intuition
// =========
//
// We will build up an algorithm for checking quorum intersection one step at
// a time.
//
// First: assume we have as a building block the ability to check a set of nodes
// for being-a-quorum. This part isn't hard and there's code implementing it
// below (QuorumIntersectionChecker::isAQuorum, though it's impelmented in terms
// of refinement 2 so don't read ahead just yet, just trust me).
//
// We could check quorum intersection for a network N via a loop like this:
//
//  foreach subset S₁ of N:
//    if S₁ is a quorum:
//      foreach subset S₂ of N:
//        if S₂ is a quorum:
//          check S₁∩ S₂≠ ∅
//
// And that would clearly suffice! It's practically the definition, rewritten in
// code, and in fact this is how we initially wrote quorum intersection
// checking. The only problem is that it is very slow: it enumerates the
// powerset P(N) of all subsets of the network, and even does so again, in a
// nested loop. This means it takes O(2ⁿ)² time. Bad.
//
// But the intuition is fine and the algorithm we wind up with is "just" a lot
// of refinements to that intuition. We're going to explore conceptually the
// same search space, just with a bunch of simplifying assumptions that let us
// skip most of it because we've convinced ourselves there are no "hits" in the
// parts we skip.
//
//
// Refinement 1: Switch to checking the complement
// ===============================================
//
// The nested testing and intersection loop above can be rewritten the following
// way while preserving logical equivalence:
//
// foreach subset S₁ of N:
//   if S₁ is a quorum:
//     for each subset S₂ of N \ S₁:
//       check that S₂ is not a quorum
//
// That is, any subset S₂ of the complement of S₁ is (by definition)
// non-intersecting with S₁ and therefore needs to be not-a-quorum if we want to
// enjoy quorum intersection. This will go a bit faster than the full cartesian
// product space of the first algorithm because as S₁ expands, N \ S₁ contracts,
// but the real improvement in complexity shows up if we introduce another
// building block (which is in fact how we implement isAQuorum anyways).
//
//
// Refinement 2: Switch to contracting sets to maximal quorums
// ===========================================================
//
// Given some set S ⊆ N, we can contract S to a maximal quorum Q ⊆ S (if it
// exists) in reasonably quick time: for each node Nᵢ ∈ S, remove Nᵢ from S if S
// does not satisfy QSᵢ, and keep iterating this procedure until it reaches a
// fixpoint. The fixpoint will either be empty (in which case S contained no
// quorum) or the largest quorum contained within S. This runs in time linear
// with the size of S (times at-worst linear-time slice checking, so maybe
// quadratic; but still far better than the exponential time of the powerset!)
//
// Where this is useful is that the algorithm from refinement 1 can now be
// adapted to seek quorums directly in the complement, rather than enumerating
// subsets of the complement:
//
// foreach subset S₁ of N:
//   if S₁ is a quorum:
//     check that (N \ S₁) contracts to the empty set (i.e. has no quorum)
//
// This frees us from the cartesian product of the powersets. Good! But we're
// still exploring the powerset in the outer loop.
//
//
// Refinement 3: Enumerate from bottom up
// ======================================
//
// We haven't mentioned yet specifically how we're going to enumerate the
// powerset P(N), and it turns out one order is especially useful for our
// purposes: "bottom up", starting from 1-element sets and expanding to
// 2-element sets, then 3-element sets, and so forth.
//
// In particular we're going to pick a recursive enumeration that's based on two
// sets: C (for "committed") and R (for "remaining"). We start with C = ∅ and R
// = N. The set C at each call is the current set we're expanding, bottom-up;
// the set R is the set we're going to draw expansions from. We pass C and R to
// the following recursive enumerator:
//
//     def enumerate(C, R):
//         fail if C is a quorum and (N \ C) has a quorum
//         return if R = ∅
//         pick some node Nᵢ ∈ R
//         call enumerate(C, R-Nᵢ)
//         call enumerate(C ∪ Nᵢ, R-Nᵢ)
//
// Any activation of this procedure is logically enumerating the powerset of
// some "perimeter set" P = C ∪ R (initially = N), but it's doing so by
// recursively dividing the perimeter in two: picking some arbitrary Nᵢ in R, and
// in the first recursive call enumerating the subsets of P that exclude Nᵢ,
// then in the second recursive call enumerating the subsets of P that include
// Nᵢ.
//
// The reason this order is useful is that it organizes the search into a
// branching tree of recursive calls that each tell us enough about their
// pending callees that we can trim some branches of that tree without actually
// calling them. The next several refinements are adding such "early exits",
// that trim the search tree.
//
//
// Refinement 4: Only scan half the space (early exit #1)
// ======================================================
//
// The first early exit is easy: just stop expanding when you get half-way
// through the space (or precisely: at sets larger than MAXSZ = (#N/2) + 1)
// because the problem is symmetric: any potential failing subset C with size
// greater than MAXSZ discovered in the branching subtree ahead will satisfy
//
//     C is a quorum and (N \ C) has a quorum
//
// and if such a C exists, it will also be discovered by some other branch of
// the search tree scanning the complement, that is enumerating subsets of (N \
// C) which has size less than MAXSZ. So there's no point looking at the
// bigger-than-half subsets in detail. So we add an exit:
//
//     def enumerate(C, R):
//         return if #C > MAXSZ                              ← new early exit
//         fail if C is a quorum and (N \ C) has a quorum
//         return if R = ∅
//         pick some node Nᵢ ∈ R
//         call enumerate(C ∪ Nᵢ, R-Nᵢ)
//         call enumerate(C, R-Nᵢ)
//
//
// Refinement 5: Look ahead for possible quorums (early exit #2.1 and 2.2)
// =======================================================================
//
// The second early exit is similarly simple: after we've checked C for quorum
// and before recursing into the next two branches, look at the "perimeter set"
// P = C ∪ R that defines the space in which the two branches will be exploring
// and check (using the contraction function) to see if there are any quorums in
// that space at all. And even more specifically, if any such (maximal) quorum
// is an extension (superset-or-equal) of C, since it will need to be if we're
// going to enumerate it in either of the remaining branches.
//
// If not, there's no point searching for specific quorums and their
// complements, and we can return early. We add the following early exits:
//
//     def enumerate(C, R):
//         return if #C > MAXSZ
//         fail if C is a quorum and (N \ C) has a quorum
//         return if R = ∅
//         return if (C ∪ R) has no quorum or                ← new early exits
//             its maximal quorum isn't a superset of C
//         pick some node Nᵢ ∈ R
//         call enumerate(C ∪ Nᵢ, R-Nᵢ)
//         call enumerate(C, R-Nᵢ)
//
//
// Refinement 6: Minimal quorums only (early exits #3.1 and 3.2)
// =============================================================
//
// So far we've been treating all quorums as equally concerning, but there is a
// key relationship we can exploit when exploring the powerset bottom-up:
// that some quorums are contained inside of other quorums.
//
// It turns out that a quorum that does not contain other quorums – a so-called
// min-quorum or minq – is sufficiently powerful to serve as a sort of
// boundary for trimming the search space. In particular, this possibly-surprising
// theorem holds:
//
//     A network enjoys quorum intersection iff every pair of minqs intersects.
//
// That is, we can redefine (while preserving equivalence) the enumeration task
// from full quorums and their complements to minqs and their complements, which
// (as we'll see) gives us another early exit. First we need to prove this
// theorem.
//
//     Forward implication: trivial. Quorum intersection is defined as "any two
//     quorums intersect". Two minqs are quorums, so they intersect by
//     assumption.
//
//     Reverse implication: by contradiction. Assume all pairs of minqs
//     intersect but some pair of quorums Q1 and Q2 do not intersect. Q1 and Q2
//     may or may not be minqs themselves, so 4 cases that all end with subsets
//     of Q1 intersecting Q2, contradicting assumption:
//
//       - If Q1 and Q2 are minqs, they intersect by assumption.
//
//       - (Two symmetric cases) If Qi is a minq and Qj is not for i != j, Qj
//         has a minq Mj inside itself (by definition of being a non-minq) and
//         Mj intersects Qi by assumption that all minqs intersect.
//
//       - If neither is a minq then each contain minqs M1 and M2 and those
//         intersect by assumption.
//
// So what is this good for? If we treat our problem as searching for minqs
// rather than more general quorums, we can do an early return in the
// enumeration any time we encounter any quorum at all: we're growing bottom-up
// from sets to supersets, but no superset of a quorum is a minq, so once we're
// at a committed set C that's a quorum there's no need to look in any further
// sub-branches of the search enlarging C: there are no more minqs down those
// branches.
//
// So we test for quorum-ness, and then for minq-ness (checking the
// complement for a non-intersecting quorum if so), and then return early in
// either case:
//
//     def enumerate(C, R):
//         return if #C > MAXSZ
//         if C is a quorum:
//             fail if C is a minq and (N \ C) has a quorum
//             return                                         ← new early exit
//         return if R = ∅
//         return if (C ∪ R) has no quorum or
//             its maximal quorum isn't a superset of C
//         pick some node Nᵢ ∈ R
//         call enumerate(C ∪ Nᵢ, R-Nᵢ)
//         call enumerate(C, R-Nᵢ)
//
//
// Refinement 7: heuristic node selection
// ======================================
//
// Observe above that we pick "some node Nᵢ ∈ R" but don't say how. It turns out
// that the node we choose has a dramatic effect on the amount of search space
// explored. Picking right means we get to an early exit (or failure) ASAP;
// picking wrong means we double the search without hitting any early exits in
// the next layer of the recursion.
//
// There's no good single answer for the best next-node to divide on; probably
// knowing this would be equivalent to solving the problem anyways. But we can
// use some heuristics. I've explored several and not come up with any better
// (empirically) than in Lachowski's initial code, so we stick with that
// heuristic here: we pick the node with the highest indegree, when looking at
// the subgraph of the remaining nodes R and edges between them. If there are
// multiple such nodes we pick among them randomly. This seems to favor
// discovering participants in quorums early, taking the quorum-related early
// exits ASAP.
//
//
// Refinement 8: Time for some graph theory
// ========================================
//
// There is one last step in the development here and it also involves minqs but
// not early exits in the enumeration as such. The enumerate function above is
// left alone, but we reduce the inputs to it from minqs in P(N) to minqs in
// P(M) for some M ⊆ N, reducing our search a lot. For this we need graph
// theory!
//
// The trick here is to recognize that there's a relationship between minqs and
// strongly connected components (SCCs) in the induced directed graph
// Gₙ. Specifically that the following theorem holds:
//
//     Any minq of N is entirely contained in an SCC of the induced graph Gₙ.
//
// Again it's worth pausing to prove by contradiction:
//
//     If some minq Q of N extended beyond an SCC of Gₙ, that means
//     (definitionally) that Q contains some node Nᵢ that depends on some node
//     Nⱼ that is not in the same SCC as Nᵢ. Since Q is a quorum, Q satisfies Nⱼ
//     by means of some slice SLⱼ ⊆ Q. Since Nⱼ is not in the same SCC as Nᵢ,
//     this SLⱼ must also not depend on nodes in the same SCC as Nᵢ. But if
//     that's so, then Nⱼ and SLⱼ together make up a subquorum of Q,
//     contradicting the assumption that Q is minimal.
//
// What's useful about the SCC relationship is that it means we can add a
// pre-filtering stage that analyzes Gₙ rather than P(N) and does two helpful
// things:
//
//     1. Check that only one SCC of Gₙ has quorums in it at all. If there are
//        two, then they contain a pair of disjoint minqs, and we're done
//        (quorum intersection does not hold).
//
//     2. Reduce the enumeration task to the powerset of the nodes of the SCC
//        that has quorums in it, rather than the powerset of all the nodes in
//        the graph. This typically excludes lots of nodes.
//
//
// Coda: micro-optimizations
// =========================
//
// We've finished with algorithmic improvements. All that remains is making it
// go as fast as possible. For this, we use graph and set representations that
// minimize allocation, hashing, indirection and so forth: vectors of dense
// bitsets and bitwise operations. These are not the same representations used
// elsewhere in stellar-core so there's a little work up front converting
// representations.
//
// Remaining details of the implementation are noted as we go, but the above
// explanation ought to give you a good idea what you're looking at.

namespace
{

using namespace stellar;
struct QBitSet;
using QGraph = std::vector<QBitSet>;

// A QBitSet is the "fast" representation of a SCPQuorumSet. It includes both a
// BitSet of its own nodes and a summary BitSet of the union of its innerSets.
struct QBitSet {
    uint32_t mThreshold;
    BitSet mNodes;
    QGraph mInnerSets;

    // Union of mNodes and all inner elements of mInnerSets.
    BitSet mAllSuccessors;

    QBitSet()
    {}
    QBitSet(uint32_t threshold,
            BitSet const& nodes,
            QGraph const& innerSets)
        : mThreshold(threshold),
          mNodes(nodes),
          mInnerSets(innerSets)
    {
        getSuccessors(mAllSuccessors);
    }

    bool empty() const {
        return mThreshold == 0 && mAllSuccessors.empty();
    }

    void log(size_t indent=0) const {
        std::string s(indent, ' ');
        CLOG(DEBUG, "SCP") << s
                           << "QBitSet: thresh=" << mThreshold
                           << "/" << (mNodes.count() + mInnerSets.size())
                           << " validators=" << mNodes;
        for (auto const& inner : mInnerSets) {
            inner.log(indent+4);
        }
    }

    void getSuccessors(BitSet &out) const {
        out |= mNodes;
        for (auto const& i : mInnerSets) {
            i.getSuccessors(out);
        }
    }
};

// This is a completely stock implementation of Tarjan's algorithm for
// calculating strongly connected components. Like "read off of wikipedia"
// stock. Go have a look!
//
// https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
struct TarjanSCCCalculator {

    struct SCCNode {
        ssize_t mIndex = {-1};
        ssize_t mLowLink = {-1};
        bool mOnStack = {false};
    };

    std::vector<SCCNode> mNodes;
    std::vector<size_t> mStack;
    size_t mIndex = {0};
    std::vector<BitSet> mSCCs;
    QGraph const& mGraph;

    TarjanSCCCalculator(QGraph const& graph)
        : mGraph(graph)
    {
    }

    void calculateSCCs() {
        mNodes.clear();
        mStack.clear();
        mIndex = 0;
        mSCCs.clear();
        for (size_t i = 0; i < mGraph.size(); ++i)
        {
            mNodes.emplace_back(SCCNode{});
        }
        for (size_t i = 0; i < mGraph.size(); ++i)
        {
            if (mNodes.at(i).mIndex == -1)
            {
                scc(i);
            }
        }
    }

    void scc(size_t i) {
        auto & v = mNodes.at(i);
        v.mIndex = mIndex;
        v.mLowLink = mIndex;
        mIndex++;
        mStack.push_back(i);
        v.mOnStack = true;

        BitSet const& succ = mGraph.at(i).mAllSuccessors;
        for (size_t j = 0; succ.next_set(j); ++j) {
            CLOG(TRACE, "SCP") << "edge: " << i << " -> " << j;
            SCCNode &w = mNodes.at(j);
            if (w.mIndex == -1)
            {
                scc(j);
                v.mLowLink = std::min(v.mLowLink, w.mLowLink);
            }
            else if (w.mOnStack)
            {
                v.mLowLink = std::min(v.mLowLink, w.mIndex);
            }
        }

        if (v.mLowLink == v.mIndex) {
            BitSet newScc;
            newScc.set(i);
            size_t j = -1;
            do
            {
                j = mStack.back();
                newScc.set(j);
                mStack.pop_back();
                mNodes.at(j).mOnStack = false;
            }
            while (j != i);
            mSCCs.push_back(newScc);
        }
    }
};

class QuorumIntersectionCheckerImpl : public QuorumIntersectionChecker
{

    Config const& mCfg;

    struct Stats {
        size_t mTotalNodes = {0};
        size_t mNumSCCs = {0};
        size_t mMaxSCC = {0};
        size_t mCallsStarted = {0};
        size_t mFirstRecursionsTaken = {0};
        size_t mSecondRecursionsTaken = {0};
        size_t mMaxQuorumsSeen = {0};
        size_t mMinQuorumsSeen = {0};
        size_t mTerminations = {0};
        size_t mEarlyExit1s = {0};
        size_t mEarlyExit21s = {0};
        size_t mEarlyExit22s = {0};
        size_t mEarlyExit31s = {0};
        size_t mEarlyExit32s = {0};
        void log() const;
    };

    // We use our own stats and a local cached flag to control tracing because
    // using the global metrics and log-partition lookups at a fine grain
    // actually becomes problematic CPU-wise.
    mutable Stats mStats;
    bool mLogTrace;

    // State to capture a counterexample found during search, for later
    // reporting.
    mutable std::pair<std::vector<PublicKey>, std::vector<PublicKey>>
        mPotentialSplit;

    // These are the key state of the checker: the mapping from node public keys
    // to graph node numbers, and the graph of QBitSets itself.
    std::vector<PublicKey> mBitNumPubKeys;
    std::unordered_map<PublicKey, size_t> mPubKeyBitNums;
    QGraph mGraph;

    // This just calculates SCCs and stores the maximal one, which we use for
    // the remainder of the search.
    TarjanSCCCalculator mTSC;
    BitSet mMaxSCC;

    QBitSet convertSCPQuorumSet(SCPQuorumSet const& sqs);
    void buildGraph(QuorumTracker::QuorumMap const& qmap);
    void buildSCCs();

    bool containsQuorumSlice(BitSet const& bs, QBitSet const& qbs) const;
    bool containsQuorumSliceForNode(BitSet const& bs, size_t node) const;
    BitSet contractToMaximalQuorum(BitSet nodes) const;
    bool isAQuorum(BitSet const& nodes) const;
    bool isMinimalQuorum(BitSet const& nodes) const;
    bool hasDisjointQuorum(BitSet const& nodes) const;
    void noteFoundDisjointQuorums(BitSet const& nodes,
                                  BitSet const& disj) const;
    std::string nodeName(size_t node) const;

    friend class MinQuorumEnumerator;

public:
    QuorumIntersectionCheckerImpl(QuorumTracker::QuorumMap const& qmap,
                                  Config const& cfg)
        : mCfg(cfg),
          mLogTrace(Logging::logTrace("SCP")),
          mTSC(mGraph)
    {
        buildGraph(qmap);
        buildSCCs();
    }

    bool networkEnjoysQuorumIntersection() const override;

    std::pair<std::vector<PublicKey>,
              std::vector<PublicKey>>
    getPotentialSplit() const override { return mPotentialSplit; }

};

void
QuorumIntersectionCheckerImpl::Stats::log() const
{
    CLOG(DEBUG, "SCP")
        << "Quorum intersection checker stats:";
    size_t exits = (mEarlyExit1s +
                    mEarlyExit21s +
                    mEarlyExit22s +
                    mEarlyExit31s +
                    mEarlyExit32s);
    CLOG(DEBUG, "SCP")
        << "[Nodes: " << mTotalNodes
        << ", SCCs: " << mNumSCCs
        << ", MaxSCC: " << mMaxSCC
        << ", MaxQs:" << mMaxQuorumsSeen
        << ", MinQs:" << mMinQuorumsSeen
        << ", Calls:" << mCallsStarted
        << ", Terms:" << mTerminations
        << ", Exits:" << exits
        << "]";
    CLOG(DEBUG, "SCP")
        << "Detailed exit stats:";
    CLOG(DEBUG, "SCP")
        << "[X1:" << mEarlyExit1s
        << ", X2.1:" << mEarlyExit21s
        << ", X2.2:" << mEarlyExit22s
        << ", X3.1:" << mEarlyExit31s
        << ", X3.2:" << mEarlyExit32s
        << "]";
}

// This function is the innermost call in the checker and must be as fast
// as possible. We spend almost all of our time in here.
bool
QuorumIntersectionCheckerImpl::containsQuorumSlice(BitSet const& bs,
                                               QBitSet const& qbs) const
{
    // First we do a very quick check: do we have enough bits in 'bs'
    // intersected with the top-level set of nodes to meet the threshold for
    // this qset?
    size_t intersecting = bs.intersection_count(qbs.mNodes);
    if (intersecting >= qbs.mThreshold)
    {
        return true;
    }

    // If not, the residual "inner threshold" is the number of additional hits
    // (in the innerSets) we need to satisfy this qset. If there aren't enough
    // innerSets for this to be possible, we can fail immediately.
    size_t innerThreshold = qbs.mThreshold - intersecting;
    if (innerThreshold > qbs.mInnerSets.size())
    {
        return false;
    }

    // Then a second quick-ish check: do we have enough bits in 'bs' intersected
    // with the union of all the successor nodes (of all innerSets) in this qset
    // to reach the threshold? This is an overapproximation of the failure case:
    // a negative result here means that even if each of the innerSets was
    // satisfied by a single bit from any of their children that intersect 'bs',
    // we still couldn't reach threshold, so there's no point looking at them in
    // finer detail.
    if (bs.intersection_count(qbs.mAllSuccessors) < qbs.mThreshold)
    {
        return false;
    }

    // To make the testing loop below a little faster still, we track both a
    // success limit -- the innerThreshold -- and a fail limit. This is the
    // number of innerSets we need to have _negative_ results on before we can
    // return a conclusive no.
    //
    // If we had a threshold of (say) 5 of 7, the fail-limit would be 3: once
    // we've failed 3 innerSets we can stop looking at the others since there's
    // no way to get to 5 successes.
    size_t innerFailLimit = qbs.mInnerSets.size() - innerThreshold + 1;
    for (auto const &inner : qbs.mInnerSets) {
        if (containsQuorumSlice(bs, inner)) {
            innerThreshold--;
            if (innerThreshold == 0) {
                return true;
            }
        } else {
            innerFailLimit--;
            if (innerFailLimit == 0) {
                return false;
            }
        }
    }
    return false;
}

bool
QuorumIntersectionCheckerImpl::containsQuorumSliceForNode(BitSet const& bs,
                                                      size_t node) const
{
    if (!bs.get(node)) {
        return false;
    }
    return containsQuorumSlice(bs, mGraph.at(node));
}

bool
QuorumIntersectionCheckerImpl::isAQuorum(BitSet const& nodes) const
{
    return (bool) contractToMaximalQuorum(nodes);
}

BitSet
QuorumIntersectionCheckerImpl::contractToMaximalQuorum(BitSet nodes) const
{
    // Find greatest fixpoint of f(X) = {n ∈ X | containsQuorumSliceForNode(X, n)}
    if (mLogTrace)
    {
        CLOG(TRACE, "SCP") << "Contracting to max quorum of " << nodes;
    }
    while (true) {
        BitSet filtered(nodes.count());
        for (size_t i = 0; nodes.next_set(i); ++i) {
            if (containsQuorumSliceForNode(nodes, i)) {
                if (mLogTrace)
                {
                    CLOG(TRACE, "SCP") << "Have qslice for " << i;
                }
                filtered.set(i);
            } else {
                if (mLogTrace)
                {
                    CLOG(TRACE, "SCP") << "Missing qslice for " << i;
                }
            }
        }
        if (filtered.count() == nodes.count() || filtered.empty()) {
            if (mLogTrace)
            {
                CLOG(TRACE, "SCP") << "Contracted to max quorum " << filtered;
            }
            if (filtered)
            {
                ++mStats.mMaxQuorumsSeen;
            }
            return filtered;
        }
        nodes = filtered;
    }
}

bool
QuorumIntersectionCheckerImpl::isMinimalQuorum(BitSet const& nodes) const
{
#ifndef NDEBUG
    // We should only be called with a quorum, such that contracting to its
    // maximum doesn't do anything. This is a slightly expensive check.
    assert(contractToMaximalQuorum(nodes) == nodes);
#endif

    BitSet minQ = nodes;
    if (!nodes) {
        // nodes isn't a quorum at all: certainly not a minq.
        return false;
    }
    for (size_t i = 0; nodes.next_set(i); ++i) {
        minQ.unset(i);
        if (isAQuorum(minQ))
        {
            // There's a subquorum with i removed: nodes isn't a minq.
            return false;
        }
        // Restore bit for next iteration.
        minQ.set(i);
    }
    // Tried every possible one-node-less subset, found no subquorums: this one
    // is minimal.
    mStats.mMinQuorumsSeen++;
    return true;
}

void
QuorumIntersectionCheckerImpl::noteFoundDisjointQuorums(BitSet const& nodes,
                                                        BitSet const& disj) const {
    mPotentialSplit.first.clear();
    mPotentialSplit.second.clear();
    CLOG(ERROR, "SCP") << "Found potential disjoint quorums";
    CLOG(DEBUG, "SCP") << "Quorum A ids: " << nodes;
    CLOG(DEBUG, "SCP") << "Quorum B ids: " << disj;
    for (size_t i = 0; nodes.next_set(i); ++i) {
        CLOG(ERROR, "SCP") << "Quorum A: " << nodeName(i);
        mPotentialSplit.first.emplace_back(mBitNumPubKeys.at(i));
    }
    CLOG(ERROR, "SCP") << "---";
    for (size_t i = 0; disj.next_set(i); ++i) {
        CLOG(ERROR, "SCP") << "Quorum B: " << nodeName(i);
        mPotentialSplit.second.emplace_back(mBitNumPubKeys.at(i));
    }
}

bool
QuorumIntersectionCheckerImpl::hasDisjointQuorum(BitSet const& nodes) const {
    BitSet disj = contractToMaximalQuorum(mMaxSCC - nodes);
    if (disj) {
        CLOG(TRACE, "SCP") << "found quorum  = " << nodes;
        CLOG(TRACE, "SCP") << "disjoint with = " << disj;
        noteFoundDisjointQuorums(nodes, disj);
    } else {
        if (mLogTrace)
        {
            CLOG(TRACE, "SCP") << "no quorum in complement  = " << (mMaxSCC - nodes);
        }
    }
    return disj;
}

void
decrementIfNonZero(size_t &sz)
{
    if (sz > 0)
    {
        --sz;
    }
}

QBitSet
QuorumIntersectionCheckerImpl::convertSCPQuorumSet(SCPQuorumSet const& sqs) {
    size_t threshold = sqs.threshold;
    BitSet nodeBits(mPubKeyBitNums.size());
    for (auto const &v : sqs.validators)
    {
        auto i = mPubKeyBitNums.find(v);
        if (i == mPubKeyBitNums.end())
        {
            // This node 'v' is one we do not have a qset for. We simulate 'v'
            // being of unknown state by both not-mentioning 'v' in the qset
            // we're building (that depends on 'v'), and by reducing the
            // threshold of the qset we're building by one: it'll pass _or_ fail
            // with one-less bit of evidence overall.
            decrementIfNonZero(threshold);
        }
        else
        {
            auto i = mPubKeyBitNums.find(v);
            assert(i != mPubKeyBitNums.end());
            nodeBits.set(i->second);
        }
    }
    QGraph inner;
    inner.reserve(sqs.innerSets.size());
    for (auto const& i : sqs.innerSets)
    {
        auto qbInner = convertSCPQuorumSet(i);
        if (qbInner.empty())
        {
            // Similarly if an innerSet has nothing in it (which happens when it
            // recursively references only unknown nodes), we treat it as though
            // it's not present either, eliding it from the converted inner
            // QGraph and decrementing our threshold further.
            decrementIfNonZero(threshold);
        }
        else
        {
            inner.emplace_back(qbInner);
        }
    }
    return QBitSet(threshold, nodeBits, inner);
}

void
QuorumIntersectionCheckerImpl::buildGraph(QuorumTracker::QuorumMap const& qmap) {
    mPubKeyBitNums.clear();
    mBitNumPubKeys.clear();
    mGraph.clear();

    for (auto const& pair : qmap) {
        if (pair.second)
        {
            size_t n = mBitNumPubKeys.size();
            mPubKeyBitNums.insert(std::make_pair(pair.first, n));
            mBitNumPubKeys.emplace_back(pair.first);
        }
        else
        {
            CLOG(DEBUG, "SCP") << "Node with missing QSet: "
                               << mCfg.toShortString(pair.first);
        }
    }

    for (auto const& pair : qmap) {
        if (pair.second) {
            auto i = mPubKeyBitNums.find(pair.first);
            assert(i != mPubKeyBitNums.end());
            auto nodeNum = i->second;
            assert(nodeNum == mGraph.size());
            auto qb = convertSCPQuorumSet(*pair.second);
            qb.log();
            mGraph.emplace_back(qb);
        }
    }
    mStats.mTotalNodes = mPubKeyBitNums.size();
}

void
QuorumIntersectionCheckerImpl::buildSCCs() {
    mTSC.calculateSCCs();
    mMaxSCC.clear();
    for (auto const& scc : mTSC.mSCCs)
    {
        if (scc.count() > mMaxSCC.count()) {
            mMaxSCC = scc;
        }
        CLOG(DEBUG, "SCP") << "Found " << scc.count() << "-node SCC " << scc;
    }
    CLOG(DEBUG, "SCP") << "Maximal SCC is " << mMaxSCC;
    mStats.mNumSCCs = mTSC.mSCCs.size();
    mStats.mMaxSCC = mMaxSCC.count();
}

// Beginning with an initial set I (which happens to be an SCC, for reasons
// discussed elsewhere), we wish to examine every min-quorum M in the powerset
// P(I), to see if M has a disjoint quorum in its complement set I \ M.
//
// To do this we form a (root) MinQuorumEnumertor and run it; this enumerator
// examines one set from P(I) to see if it's a min-quorum (with a disjoint
// partner), and then builds two recursive child sub-enumerators, each of which
// examines half of the remaining powerset P(I).
//
// As described so far, this process would be exponential-time in the size of I.
// But: the structure of the exploration of P(I) is "bottom up", from all the
// smallest subsets in the powerset to largest, one additional node at a time.
// And in this order of exploration there are several facts we can observe along
// the way that imply the absence of further min-quorums in the remaining
// subspace of larger subsets, along each path of the recurrence. Those
// observations allow us to return early in the recurrence in many cases,
// trimming the search space dramatically.

class MinQuorumEnumerator {

    // Set of nodes "committed to" in this branch of the recurrence. In other
    // words: set of nodes that this enumerator and its children will definitely
    // include in every subset S of P(I) that they examine. This set will remain
    // the same (omitting the split node) in one child, and expand (including
    // the split node) in the other child.
    BitSet mCommitted;

    // Set of nodes that remain to be powerset-expanded in the recurrence.  In
    // other words: the subspace of P(I) that this enumerator and its children
    // are responsible for is { committed ∪ r | r ∈ P(remaining) }. This set
    // will strictly decrease (by the split node) in both children.
    BitSet mRemaining;

    // The set (committed ∪ remaining) which is a bound on the set of nodes in
    // any set enumerated by this enumerator and its children.
    BitSet mPerimeter;


    // Checker that owns us, contains state of stats, graph, etc.
    QuorumIntersectionCheckerImpl const &mQic;

public:

    MinQuorumEnumerator(BitSet const& committed, BitSet const& remaining,
                        QuorumIntersectionCheckerImpl const &qic)
        : mCommitted(committed),
          mRemaining(remaining),
          mPerimeter(committed | remaining),
          mQic(qic)
    {}

    // Slightly tweaked variant of Lachowski's next-node function.
    size_t pickSplitNode() const {
        std::vector<size_t> inDegrees(mQic.mGraph.size(), 0);
        assert(!mRemaining.empty());
        size_t maxNode = mRemaining.max();
        size_t maxCount = 1;
        size_t maxDegree = 0;
        for (size_t i = 0; mRemaining.next_set(i); ++i) {

            // Heuristic opportunity: biasing towards cross-org edges and
            // away from intra-org edges seems to help; work out some way
            // to make this a robust bias.
            BitSet avail = mQic.mGraph.at(i).mAllSuccessors & mRemaining;
            for (size_t j = 0; avail.next_set(j); ++j)
            {
                size_t currDegree = ++inDegrees.at(j);
                if (currDegree >= maxDegree)
                {
                    if (currDegree == maxDegree)
                    {
                        // currDegree same as existing max: replace it
                        // only probabilistically.
                        maxCount++;
                        if (rand_flip())
                        {
                            // Not switching max element with max degree.
                            continue;
                        }
                        // Switching max element with max degree.
                    }
                    else
                    {
                        // currDegree strictly greater, reset replica count.
                        maxCount = 1;
                    }
                    maxDegree = currDegree;
                    maxNode = j;
                }
            }
        }
        return maxNode;
    }

    size_t maxCommit() const {
        return (mQic.mMaxSCC.count() / 2) + 1;
    }

    bool anyMinQuorumHasDisjointQuorum() {
        mQic.mStats.mCallsStarted++;

        // Emit a progress meter every million calls.
        if ((mQic.mStats.mCallsStarted & 0xfffff) == 0) {
            mQic.mStats.log();
        }
        if (mQic.mLogTrace)
        {
            CLOG(TRACE, "SCP") << "exploring with committed=" << mCommitted;
            CLOG(TRACE, "SCP") << "exploring with remaining=" << mRemaining;
        }

        // First early exit: we can avoid looking for further min-quorums if
        // we're committed to more than half the SCC plus 1: the other branches
        // of the search will find them instead, within the complement of a
        // min-quorum they find (if they find any).
        if (mCommitted.count() > maxCommit()) {
            mQic.mStats.mEarlyExit1s++;
            if (mQic.mLogTrace)
            {
                CLOG(TRACE, "SCP") << "early exit 1, with committed=" << mCommitted;
            }
            return false;
        }

        // Principal enumeration branch and third early exit: stop when
        // committed has grown to a quorum, enumerating it if it's a
        // min-quorum. Whether it's a min-quorum or just a normal quorum, any
        // extension _won't_ be a min-quorum, since it will have this quorum as
        // a subquorum, so both cases are terminal.
        if (mQic.mLogTrace)
        {
            CLOG(TRACE, "SCP") << "checking for quorum in committed="
                               << mCommitted;
        }
        if (auto committedQuorum = mQic.contractToMaximalQuorum(mCommitted)) {
            if (mQic.isMinimalQuorum(committedQuorum)) {
                // Found a min-quorum. Examine it to see if
                // there's a disjoint quorum.
                if (mQic.mLogTrace)
                {
                    CLOG(TRACE, "SCP") << "early exit 3.1: minimal quorum="
                                       << committedQuorum;
                }
                mQic.mStats.mEarlyExit31s++;
                return mQic.hasDisjointQuorum(committedQuorum);
            }
            if (mQic.mLogTrace)
            {
                CLOG(TRACE, "SCP") << "early exit 3.2: non-minimal quorum="
                                   << committedQuorum;
            }
            mQic.mStats.mEarlyExit32s++;
            return false;
        }

        // Second early exit: stop if there isn't at least one quorum to
        // enumerate in the remaining perimeter that's an extension of the
        // existing committed set.
        if (mQic.mLogTrace)
        {
            CLOG(TRACE, "SCP") << "checking for quorum in perimeter=" << mPerimeter;
        }
        if (auto extensionQuorum = mQic.contractToMaximalQuorum(mPerimeter)) {
            if (! (mCommitted <= extensionQuorum)) {
                if (mQic.mLogTrace)
                {
                    CLOG(TRACE, "SCP") << "early exit 2.2: extension quorum="
                                       << extensionQuorum << " in perimeter="
                                       << mPerimeter << " does not extend committed="
                                       << mCommitted;
                }
                mQic.mStats.mEarlyExit22s++;
                return false;
            }
        } else {
            if (mQic.mLogTrace)
            {
                CLOG(TRACE, "SCP") << "early exit 2.1: no extension quorum in perimeter="
                                   << mPerimeter;
            }
            mQic.mStats.mEarlyExit21s++;
            return false;
        }

        // Principal termination condition: stop when remainder is empty.
        if (!mRemaining) {
            mQic.mStats.mTerminations++;
            if (mQic.mLogTrace)
            {
                CLOG(TRACE, "SCP") << "remainder exhausted";
            }
            return false;
        }

        // Phase two: recurse into subproblems.
        size_t split = pickSplitNode();
        if (mQic.mLogTrace)
        {
            CLOG(TRACE, "SCP") << "recursing into subproblems, split=" << split;
        }
        mRemaining.unset(split);
        MinQuorumEnumerator childExcludingSplit(mCommitted, mRemaining, mQic);
        mQic.mStats.mFirstRecursionsTaken++;
        if (childExcludingSplit.anyMinQuorumHasDisjointQuorum()) {
            if (mQic.mLogTrace)
            {
                CLOG(TRACE, "SCP") << "first subproblem returned true, missing split="
                                   << split;
            }
            return true;
        }
        mCommitted.set(split);
        MinQuorumEnumerator childIncludingSplit(mCommitted, mRemaining, mQic);
        mQic.mStats.mSecondRecursionsTaken++;
        return childIncludingSplit.anyMinQuorumHasDisjointQuorum();
    }
};

std::string
QuorumIntersectionCheckerImpl::nodeName(size_t node) const
{
    return mCfg.toShortString(mBitNumPubKeys.at(node));
}

bool
QuorumIntersectionCheckerImpl::networkEnjoysQuorumIntersection() const {
    // First stage: check the graph-level SCCs for disjoint quorums,
    // and filter out nodes that aren't in the main SCC.
    bool foundDisjoint = false;
    size_t nNodes = mPubKeyBitNums.size();
    CLOG(INFO, "SCP") << "Calculating " << nNodes
                      << "-node network quorum intersection";

    for (auto const& scc : mTSC.mSCCs) {
        if (scc == mMaxSCC) {
            continue;
        }
        if (auto other = contractToMaximalQuorum(scc)) {
            CLOG(DEBUG, "SCP") << "found SCC-djsoint quorum = " << other;
            CLOG(DEBUG, "SCP") << "djsoint from quorum = " << contractToMaximalQuorum(mMaxSCC);
            noteFoundDisjointQuorums(contractToMaximalQuorum(mMaxSCC), other);
            foundDisjoint = true;
            break;
        } else {
            CLOG(DEBUG, "SCP") << "SCC contains no quorums = " << scc;
            for (size_t i = 0; scc.next_set(i); ++i) {
                CLOG(DEBUG, "SCP") << "Node outside main SCC: "
                                   << nodeName(i);
            }
        }
    }
    for (size_t i = 0; mMaxSCC.next_set(i); ++i)
    {
        CLOG(DEBUG, "SCP") << "Main SCC node: " << nodeName(i);
    }

    auto q = contractToMaximalQuorum(mMaxSCC);
    if (q)
    {
        CLOG(DEBUG, "SCP") << "Maximal main SCC quorum: "
                           << q;
    }
    else
    {
        // We vacuously "enjoy quorum intersection" if there are no quorums,
        // though this is probably enough of a potential problem itself that
        // it's worth warning about.
        CLOG(WARNING, "SCP") << "Main SCC contains no (maximal) quorum!";
        return true;
    }

    // Second stage: scan the main SCC powerset, potentially expensive.
    if (!foundDisjoint)
    {
        BitSet committed;
        BitSet remaining = mMaxSCC;
        MinQuorumEnumerator mqe(committed, remaining, *this);
        foundDisjoint = mqe.anyMinQuorumHasDisjointQuorum();
        mStats.log();
    }
    return !foundDisjoint;
}

}

namespace stellar
{
std::shared_ptr<QuorumIntersectionChecker>
QuorumIntersectionChecker::create(QuorumTracker::QuorumMap const& qmap,
                                  Config const& cfg)
{
    return std::make_shared<QuorumIntersectionCheckerImpl>(qmap, cfg);
}
}
