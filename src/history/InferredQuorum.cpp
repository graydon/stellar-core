#include "history/InferredQuorum.h"
#include "crypto/SHA.h"
#include "util/BitsetEnumerator.h"
#include "util/format.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"
#include <fstream>
#include <sstream>
#include <cvc4/cvc4.h>

namespace stellar
{

void
InferredQuorum::noteSCPHistory(SCPHistoryEntry const& hist)
{
    for (auto const& qset : hist.v0().quorumSets)
    {
        noteQset(qset);
    }
    for (auto const& msg : hist.v0().ledgerMessages.messages)
    {
        auto pk = msg.statement.nodeID;
        notePubKey(pk);
        auto const& pledges = msg.statement.pledges;
        switch (pledges.type())
        {
        case SCP_ST_PREPARE:
            noteQsetHash(pk, pledges.prepare().quorumSetHash);
            break;
        case SCP_ST_CONFIRM:
            noteQsetHash(pk, pledges.confirm().quorumSetHash);
            break;
        case SCP_ST_EXTERNALIZE:
            noteQsetHash(pk, pledges.externalize().commitQuorumSetHash);
            break;
        case SCP_ST_NOMINATE:
            noteQsetHash(pk, pledges.nominate().quorumSetHash);
            break;
        }
    }
}

void
InferredQuorum::noteQsetHash(PublicKey const& pk, Hash const& qsetHash)
{
    auto range = mQsetHashes.equal_range(pk);
    for (auto i = range.first; i != range.second; ++i)
    {
        if (i->second == qsetHash)
        {
            // Already noted, quit now.
            return;
        }
    }
    mQsetHashes.insert(std::make_pair(pk, qsetHash));
}

void
InferredQuorum::noteQset(SCPQuorumSet const& qset)
{
    Hash qSetHash = sha256(xdr::xdr_to_opaque(qset));
    if (mQsets.find(qSetHash) == mQsets.end())
    {
        mQsets.insert(std::make_pair(qSetHash, qset));
    }
    for (auto const& pk : qset.validators)
    {
        notePubKey(pk);
    }
    for (auto const& inner : qset.innerSets)
    {
        noteQset(inner);
    }
}

void
InferredQuorum::notePubKey(PublicKey const& pk)
{
    mPubKeys[pk]++;
}

static std::shared_ptr<BitsetEnumerator>
makeQsetEnumerator(SCPQuorumSet const& qset,
                   std::unordered_map<PublicKey, size_t> const& nodeNumbers)
{
    std::vector<std::shared_ptr<BitsetEnumerator>> innerEnums;
    for (auto const& v : qset.validators)
    {
        auto i = nodeNumbers.find(v);
        assert(i != nodeNumbers.end());
        innerEnums.push_back(ConstantEnumerator::bitNumber(i->second));
    }
    for (auto const& s : qset.innerSets)
    {
        innerEnums.push_back(makeQsetEnumerator(s, nodeNumbers));
    }
    return std::make_shared<SelectionEnumerator>(
        std::make_shared<PermutationEnumerator>(qset.threshold,
                                                innerEnums.size()),
        innerEnums);
}

static std::shared_ptr<BitsetEnumerator>
makeSliceEnumerator(InferredQuorum const& iq, PublicKey const& pk,
                    std::unordered_map<PublicKey, size_t> const& nodeNumbers)
{
    // Enumerating a slice is the cartesian product enumeration of a
    // constant enumerator (for the node itself) and a selection enumerator
    // that does n-of-k for its validators and subqsets.
    std::vector<std::shared_ptr<BitsetEnumerator>> innerEnums;

    auto i = nodeNumbers.find(pk);
    assert(i != nodeNumbers.end());
    innerEnums.push_back(ConstantEnumerator::bitNumber(i->second));

    auto qsh = iq.mQsetHashes.find(pk);
    assert(qsh != iq.mQsetHashes.end());

    auto qs = iq.mQsets.find(qsh->second);
    assert(qs != iq.mQsets.end());

    innerEnums.push_back(makeQsetEnumerator(qs->second, nodeNumbers));
    return std::make_shared<CartesianProductEnumerator>(innerEnums);
}

static bool isQuorum(std::bitset<64> const& q, InferredQuorum const& iq,
                     std::unordered_map<PublicKey, size_t> const& nodeNumbers,
                     std::vector<PublicKey> const& revNodeNumbers)
{
    for (size_t i = 0; i < q.size(); ++i)
    {
        if (q.test(i))
        {
            auto e = makeSliceEnumerator(iq, revNodeNumbers.at(i), nodeNumbers);
            if (!e)
            {
                return false;
            }
            bool containsSliceForE = false;
            while (*e)
            {
                // If we find _any_ slice in e's slices that
                // is covered by q, we're good.
                if ((q | **e) == q)
                {
                    containsSliceForE = true;
                    break;
                }
                ++(*e);
            }
            if (!containsSliceForE)
            {
                return false;
            }
        }
    }
    return true;
}

class NodeExprBiMap {
    CVC4::ExprManager &mExprManager;
    std::map<PublicKey, std::shared_ptr<CVC4::Expr>> mNodes;
    std::map<std::shared_ptr<CVC4::Expr>, PublicKey> mRevNodes;
public:
    NodeExprBiMap(CVC4::ExprManager &em) : mExprManager(em) {}
    std::shared_ptr<CVC4::Expr> getExprForNode(PublicKey const& pk) {
        auto i = mNodes.find(pk);
        if (i != mNodes.end()) {
            return i->second;
        } else {
            size_t i = mNodes.size();
            CLOG(INFO, "History") << "creating const node for " << i;
            std::shared_ptr<CVC4::Expr> e =
                std::make_shared<CVC4::Expr>(mExprManager.mkConst(CVC4::Rational(i)));
            mNodes.insert(std::make_pair(pk, e));
            mRevNodes.insert(std::make_pair(e, pk));
            return e;
        }
    }
    PublicKey const& getNodeForExpr(std::shared_ptr<CVC4::Expr> e) {
        auto i = mRevNodes.find(e);
        assert(i != mRevNodes.end());
        return i->second;
    }
};

static CVC4::Expr qSetSatisfiedByQuorum(CVC4::ExprManager& em,
                                        std::string const& parentName,
                                        CVC4::SetType const& nodeSetTy,
                                        NodeExprBiMap &nodes,
                                        CVC4::Expr const& empty,
                                        SCPQuorumSet const& qset,
                                        CVC4::Expr const& quorum)
{
    using namespace CVC4;
    // Each qset S has a set of validators and a set of innerSets. S is
    // satsified by a quorum Q iff S.validators is a subset of Q, and [the sum
    // of card(S.validators) and (ite
    // qsetSatisfiedByQuorum(...,S.innerSets[i],...) 1 0) for all innerSets]
    // exceeds S.threshold.
    Expr validators = em.mkVar(fmt::format("{}.validators", parentName), nodeSetTy);
    std::vector<Expr> candidateValidatorExprs;
    for (auto const& v : qset.validators) {
        candidateValidatorExprs.push_back(*nodes.getExprForNode(v));
    }
    candidateValidatorExprs.push_back(empty);
    Expr candidateValidators = (candidateValidatorExprs.size() == 1 ? empty :
                                em.mkExpr(kind::INSERT, candidateValidatorExprs));
    Expr vCard = em.mkExpr(kind::CARD, validators);

    Expr zero = em.mkConst(Rational(0));
    Expr one = em.mkConst(Rational(1));
    std::vector<Expr> summandExprs = { vCard, zero };
    for (size_t i = 0; i < qset.innerSets.size(); ++i) {
        std::string innerSetName = fmt::format("{}.innerset_{}", parentName, i);
        Expr innerSetIsSatisfied = qSetSatisfiedByQuorum(em, innerSetName,
                                                         nodeSetTy, nodes, empty,
                                                         qset.innerSets[i], quorum);
        summandExprs.push_back(em.mkExpr(kind::ITE, innerSetIsSatisfied, one, zero));
    }

    Expr thresholdMet = em.mkExpr(kind::GEQ,
                                  em.mkExpr(kind::PLUS, summandExprs),
                                  em.mkConst(Rational(qset.threshold)));
    return em.mkExpr(kind::AND,
                     em.mkExpr(kind::SUBSET, validators, quorum),
                     em.mkExpr(kind::SUBSET, validators, candidateValidators),
                     thresholdMet);
}

bool
InferredQuorum::checkQuorumIntersectionViaCvc(Config const& cfg) const
{
    using namespace CVC4;
    ExprManager em;
    SmtEngine smt(&em);
    LogicInfo logic = smt.getLogicInfo();
    //logic.enableEverything();
    logic.enableTheory(theory::THEORY_SETS);
    smt.setLogic(logic);
    //smt.setOption("incremental", true);
    smt.setOption("produce-models", true);
    smt.setOption("produce-assertions", true);

    // Definition (quorum). A set of nodes U ⊆ V in FBAS ⟨V,Q⟩ is a quorum
    // iff U =/= ∅ and U contains a slice for each member -- i.e., ∀ v ∈ U,
    // ∃ q ∈ Q(v) such that q ⊆ U.
    //
    // Definition (quorum intersection). An FBAS enjoys quorum intersection
    // iff any two of its quorums share a node—i.e., for all quorums U1 and
    // U2, U1 ∩ U2 =/= ∅.

    // Make an integer-expr from 0..numNodes for each node.
    NodeExprBiMap nodes(em);
    for (auto const& n : mPubKeys)
    {
        nodes.getExprForNode(n.first);
    }

    Type nodeTy = em.integerType();
    SetType nodeSetTy = em.mkSetType(nodeTy);
    Expr quorumA = em.mkVar("QuorumA", nodeSetTy);
    Expr quorumB = em.mkVar("QuorumB", nodeSetTy);
    Expr allQsetNodes = em.mkVar("AllQsetNodes", nodeSetTy);
    Expr empty = em.mkConst(EmptySet(nodeSetTy));
    smt.assertFormula(em.mkExpr(kind::DISTINCT, empty, quorumA));
    smt.assertFormula(em.mkExpr(kind::DISTINCT, empty, quorumB));
    smt.assertFormula(em.mkExpr(kind::DISTINCT, quorumA, quorumB));
    smt.assertFormula(
        em.mkExpr(kind::EQUAL, empty,
                  em.mkExpr(kind::INTERSECTION, quorumA, quorumB)));

    // We're only going to encode node-in-quorum membership and qset
    // satisfaction for nodes we _have_ qsets for, which might be significantly
    // fewer than the total set of nodes; we can't really tell how nodes we
    // don't have qsets for will behave in a network; we exclude them.
    std::vector<Expr> allQsetNodeExprs;
    std::vector<Expr> allQsetDisjuncts;
    size_t nQsets = 0;
    for (auto const& n : mQsetHashes) {
        std::shared_ptr<Expr> nodeExpr = nodes.getExprForNode(n.first);
        allQsetNodeExprs.push_back(*nodeExpr);

        auto qi = mQsets.find(n.second);
        assert(qi != mQsets.end());
        SCPQuorumSet qset = qi->second;

        // For each qset-having node, we form a disjunct of the possibility that
        // the node is in quorum A (and the conjunct that quorum A satisfies its
        // qset) and the possibility that the node is in quorum B (and the
        // conjuct that quorum B satisfies its qset).
        Expr nodeIsInA = em.mkExpr(kind::MEMBER, *nodeExpr, quorumA);
        Expr qsetIsSatisfiedByA =
            qSetSatisfiedByQuorum(em, fmt::format("node_{}_qset_in_A", nQsets),
                                  nodeSetTy, nodes, empty, qset, quorumA);
        Expr nodeIsInB = em.mkExpr(kind::MEMBER, *nodeExpr, quorumB);
        Expr qsetIsSatisfiedByB =
            qSetSatisfiedByQuorum(em, fmt::format("node_{}_qset_in_B", nQsets),
                                  nodeSetTy, nodes, empty, qset, quorumB);
        Expr conjA = em.mkExpr(kind::AND, nodeIsInA, qsetIsSatisfiedByA);
        Expr conjB = em.mkExpr(kind::AND, nodeIsInB, qsetIsSatisfiedByB);
        Expr disj = em.mkExpr(kind::OR, conjA, conjB);
        allQsetDisjuncts.push_back(disj);
        ++nQsets;
    }
    allQsetNodeExprs.push_back(empty);
    smt.assertFormula(em.mkExpr(kind::EQUAL, allQsetNodes,
                                em.mkExpr(kind::INSERT, allQsetNodeExprs)));
    smt.assertFormula(em.mkExpr(kind::SUBSET, quorumA, allQsetNodes));
    smt.assertFormula(em.mkExpr(kind::SUBSET, quorumB, allQsetNodes));
    smt.assertFormula(em.mkExpr(kind::AND, allQsetDisjuncts));

    Result res = smt.checkSat();
    if (res.isSat()) {
        CLOG(WARNING, "History")
            << "Warning: CVC found pair of non-intersecting quorums:";
        std::vector<Expr> quorums = {quorumA, quorumB};
        for (auto const& q : quorums) {
            Expr concreteQ = smt.getValue(q);
            CLOG(WARNING, "History") << q.toString() << " : " << concreteQ.toString();
        }
    } else {
        CLOG(INFO, "History")
            << nQsets << "-node FBAS enjoys quorum intersection according to CVC";
        CLOG(INFO, "History")
            << "In other words, the following CVC assertions are deemed not satisfiable:";
        for (auto const &e : smt.getAssertions()) {
            CLOG(INFO, "History")
                << "ASSERT " << e.toString() << ";";
        }
    }

    smt.getStatistics().flushInformation(std::cout);
    return !res.isSat();
}

bool
InferredQuorum::checkQuorumIntersection(Config const& cfg) const
{
    // Definition (quorum). A set of nodes U ⊆ V in FBAS ⟨V,Q⟩ is a quorum
    // iff U =/= ∅ and U contains a slice for each member -- i.e., ∀ v ∈ U,
    // ∃ q ∈ Q(v) such that q ⊆ U.
    //
    // Definition (quorum intersection). An FBAS enjoys quorum intersection
    // iff any two of its quorums share a node—i.e., for all quorums U1 and
    // U2, U1 ∩ U2 =/= ∅.

    // Assign a bit-number to each node
    std::unordered_map<PublicKey, size_t> nodeNumbers;
    std::vector<PublicKey> revNodeNumbers;
    for (auto const& n : mPubKeys)
    {
        nodeNumbers.insert(std::make_pair(n.first, nodeNumbers.size()));
        revNodeNumbers.push_back(n.first);
    }

    // We're (only) going to scan the powerset of the nodes we _have_ qsets
    // for, which might be significantly fewer than the total set of nodes;
    // we can't really tell how nodes we don't have qsets for will behave
    // in a network; we exclude them.
    std::unordered_set<size_t> nodesWithQsets;
    std::vector<std::shared_ptr<BitsetEnumerator>> nodeEnumerators;
    for (auto const& n : mQsetHashes)
    {
        assert(mQsets.find(n.second) != mQsets.end());
        auto i = nodeNumbers.find(n.first);
        assert(i != nodeNumbers.end());
        nodesWithQsets.insert(i->second);
    }
    for (auto nwq : nodesWithQsets)
    {
        nodeEnumerators.push_back(ConstantEnumerator::bitNumber(nwq));
    }

    // Build an enumerator for the powerset of the nodes we have qsets for;
    // this will thus return _candidate_ quorums, each of which we'll check
    // for quorum-ness.
    SelectionEnumerator quorumCandidateEnumerator(
        std::make_shared<PowersetEnumerator>(nodeEnumerators.size()),
        nodeEnumerators);

    assert(nodeEnumerators.size() < 64);
    uint64_t lim = 1ULL << nodeEnumerators.size();
    CLOG(INFO, "History") << "Scanning: " << lim
                          << " possible node subsets (of "
                          << nodeEnumerators.size() << " nodes with qsets)";

    // Enumerate all the quorums, de-duplicating into a hashset
    std::unordered_set<uint64_t> allQuorums;
    while (quorumCandidateEnumerator)
    {
        auto bv = *quorumCandidateEnumerator;
        if (isQuorum(bv, *this, nodeNumbers, revNodeNumbers))
        {
            CLOG(INFO, "History") << "Quorum: " << bv;
            allQuorums.insert(bv.to_ullong());
        }
        ++quorumCandidateEnumerator;
    }

    // Report what we found.
    for (auto const& pk : mPubKeys)
    {
        if (mQsetHashes.find(pk.first) == mQsetHashes.end())
        {
            CLOG(WARNING, "History")
                << "Node without qset: " << cfg.toShortString(pk.first);
        }
    }
    CLOG(INFO, "History") << "Found " << nodeNumbers.size() << " nodes total";
    CLOG(INFO, "History") << "Found " << nodeEnumerators.size()
                          << " nodes with qsets";
    CLOG(INFO, "History") << "Found " << allQuorums.size() << " quorums";

    bool allOk = true;
    for (auto const& q : allQuorums)
    {
        for (auto const& v : allQuorums)
        {
            if (q != v)
            {
                if (!(q & v))
                {
                    allOk = false;
                    CLOG(WARNING, "History")
                        << "Warning: found pair of non-intersecting quorums";
                    CLOG(WARNING, "History") << std::bitset<64>(q);
                    CLOG(WARNING, "History") << "vs.";
                    CLOG(WARNING, "History") << std::bitset<64>(v);
                }
            }
        }
    }

    if (allOk)
    {
        CLOG(INFO, "History") << "Network of " << nodeEnumerators.size()
                              << " nodes enjoys quorum intersection: ";
    }
    else
    {
        CLOG(WARNING, "History")
            << "Network of " << nodeEnumerators.size()
            << " nodes DOES NOT enjoy quorum intersection: ";
    }
    for (auto n : nodesWithQsets)
    {
        auto isAlias = false;
        auto name = cfg.toStrKey(revNodeNumbers.at(n), isAlias);
        if (allOk)
        {
            CLOG(INFO, "History")
                << "  \"" << (isAlias ? "$" : "") << name << '"';
        }
        else
        {
            CLOG(WARNING, "History")
                << "  \"" << (isAlias ? "$" : "") << name << '"';
        }
    }
    return allOk;
}

std::string
InferredQuorum::toString(Config const& cfg) const
{
    std::ostringstream out;

    // By default we will emit only those keys involved in half or
    // more of the quorums we've observed them in. This could be made
    // more clever.
    size_t thresh = 0;
    for (auto const& pair : mPubKeys)
    {
        thresh = pair.second > thresh ? pair.second : thresh;
    }
    thresh >>= 2;

    for (auto const& pair : mPubKeys)
    {
        auto isAlias = false;
        auto name = cfg.toStrKey(pair.first, isAlias);
        if (pair.second < thresh)
        {
            out << "# skipping unreliable "
                << "(" << pair.second << "/" << thresh << ") node: " << '"'
                << (isAlias ? "$" : "") << name << '"' << std::endl;
        }
    }

    out << "[QUORUM_SET]" << std::endl;
    out << "[" << std::endl;
    auto first = true;
    for (auto const& pair : mPubKeys)
    {
        if (pair.second < thresh)
        {
            continue;
        }
        auto isAlias = false;
        auto name = cfg.toStrKey(pair.first, isAlias);
        if (first)
        {
            first = false;
        }
        else
        {
            out << "," << std::endl;
        }
        out << '"' << (isAlias ? "$" : "") << name << '"';
    }
    out << std::endl << "]" << std::endl;
    return out.str();
}

void
InferredQuorum::writeQuorumGraph(Config const& cfg, std::ostream& out) const
{
    out << "digraph {" << std::endl;
    for (auto const& pkq : mQsetHashes)
    {
        auto qp = mQsets.find(pkq.second);
        if (qp != mQsets.end())
        {
            auto src = cfg.toShortString(pkq.first);
            for (auto const& dst : qp->second.validators)
            {
                out << src << " -> " << cfg.toShortString(dst) << ";"
                    << std::endl;
            }
            for (auto const& iqs : qp->second.innerSets)
            {
                for (auto const& dst : iqs.validators)
                {
                    out << src << " -> " << cfg.toShortString(dst) << ";"
                        << std::endl;
                }
            }
        }
    }
    out << "}" << std::endl;
}
}
