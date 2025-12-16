#include "pdte.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include <memory>
#include <stdexcept>
#include <limits>

#include <cryptoTools/Common/TestCollection.h>

#include <RingOA/protocol/integer_comparison.h>
#include <RingOA/protocol/key_io.h>
#include <RingOA/protocol/ringoa.h>
#include <RingOA/protocol/shared_ot.h>
#include <RingOA/sharing/additive_2p.h>
#include <RingOA/sharing/additive_3p.h>
#include <RingOA/sharing/share_io.h>
#include <RingOA/utils/logger.h>
#include <RingOA/utils/network.h>
#include <RingOA/utils/to_string.h>
#include <RingOA/utils/utils.h>
#include <RingOA/utils/rng.h>

namespace {

const std::string kCurrentPath = ringoa::GetCurrentDirectory();
const std::string kTestOSPath  = kCurrentPath + "/data/test/";

}    // namespace

namespace test_ringoa {

using ringoa::Channels;
using ringoa::FileIo;
using ringoa::Logger;
using ringoa::Mod2N;
using ringoa::ThreePartyNetworkManager;
using ringoa::ToString, ringoa::Format;
using ringoa::fss::EvalType;
using ringoa::proto::IntegerComparisonEvaluator;
using ringoa::proto::IntegerComparisonKey;
using ringoa::proto::IntegerComparisonKeyGenerator;
using ringoa::proto::IntegerComparisonParameters;
using ringoa::proto::KeyIo;
using ringoa::proto::RingOaEvaluator;
using ringoa::proto::RingOaKey;
using ringoa::proto::RingOaKeyGenerator;
using ringoa::proto::RingOaParameters;
using ringoa::proto::SharedOtEvaluator;
using ringoa::proto::SharedOtKey;
using ringoa::proto::SharedOtKeyGenerator;
using ringoa::proto::SharedOtParameters;
using ringoa::sharing::AdditiveSharing2P;
using ringoa::sharing::ReplicatedSharing3P;
using ringoa::sharing::RepShare64, ringoa::sharing::RepShareVec64, ringoa::sharing::RepShareView64;
using ringoa::sharing::ShareIo;

namespace {

constexpr uint32_t kTreeDepth    = 10;
constexpr uint64_t kNodeCount    = 1ULL << kTreeDepth;
constexpr uint64_t kFeatureCount = 4;
constexpr uint32_t kRingBits     = 13;

// feature vectorの要素はフィボナッチ数列とする
std::vector<uint64_t> BuildFeatureVector() {
    std::vector<uint64_t> features(kFeatureCount, 0);
    if (kFeatureCount == 0)
        return features;

    uint64_t prev = 1;
    uint64_t curr = 2;
    features[0]   = prev;
    for (uint64_t i = 1; i < kFeatureCount; ++i) {
        features[i] = curr;
        uint64_t next = prev + curr;
        prev          = curr;
        curr          = next;
    }
    return features;
}

// ノード情報を1つの配列に詰め込むため
// 鍵が1つで済む
constexpr uint64_t kThresholdOffset  = 0;
constexpr uint64_t kLeftOffset       = kThresholdOffset + kNodeCount;
constexpr uint64_t kRightOffset      = kLeftOffset + kNodeCount;
constexpr uint64_t kFeatureValOffset = kRightOffset + kNodeCount;
constexpr uint64_t kLabelOffset      = kFeatureValOffset + kNodeCount;
constexpr uint64_t kLayoutEntries    = kLabelOffset + kNodeCount;

// 平文の決定木構造
struct TreeNodePlain {
    uint64_t threshold;
    uint64_t left;
    uint64_t right;
    uint64_t feature_id;
    uint64_t label;
};

// 後続でMCPの結果と突き合わせ
uint64_t EvaluateTreePlain(const std::vector<TreeNodePlain> &tree, const std::vector<uint64_t> &features) {
    uint64_t idx = 0;
    Logger::InfoLog(LOC, "[PlainEval] Starting with idx=" + ToString(idx));
    for (uint32_t depth = 0; depth < kTreeDepth; ++depth) {
        const auto &node = tree[idx];
        uint64_t     fid = node.feature_id % features.size();
        uint64_t     fv  = features[fid];
        bool         cmp = (fv < node.threshold);
        uint64_t     next_idx = cmp ? node.left : node.right;
        Logger::InfoLog(LOC, "[PlainEval][depth " + ToString(depth) + "] idx=" + ToString(idx) + 
                        " fid=" + ToString(fid) + " fv=" + ToString(fv) + " thr=" + ToString(node.threshold) + 
                        " cmp=" + ToString(cmp) + " left=" + ToString(node.left) + " right=" + ToString(node.right) + 
                        " next_idx=" + ToString(next_idx) + " label=" + ToString(node.label));
        idx = next_idx;
        if (idx >= tree.size()) {
            Logger::InfoLog(LOC, "[PlainEval] idx >= tree.size(), clamping to " + ToString(tree.size() - 1));
            idx = tree.size() - 1;
        }
    }
    Logger::InfoLog(LOC, "[PlainEval] Final idx=" + ToString(idx) + " label=" + ToString(tree[idx].label));
    return tree[idx].label;
}

void SaveIntegerComparisonKey(const std::string &path, const IntegerComparisonKey &key) {
    std::vector<uint8_t> buffer;
    key.Serialize(buffer);
    std::ofstream ofs(path, std::ios::binary);
    ofs.write(reinterpret_cast<const char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    if (!ofs)
        throw std::runtime_error("Failed to write DPF key to " + path);
}

void LoadIntegerComparisonKey(const std::string &path, IntegerComparisonKey &key) {
    std::ifstream ifs(path, std::ios::binary);
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (!ifs.good() && !ifs.eof())
        throw std::runtime_error("Failed to read DPF key from " + path);
    key.Deserialize(buffer);
}

}    // namespace

void Pdte_Offline_Test() {
    Logger::DebugLog(LOC, "Pdte_Offline_Test...");

    RingOaParameters ringoa_params(kRingBits);
    uint64_t         ring_bits = ringoa_params.GetParameters().GetInputBitsize();
    IntegerComparisonParameters ic_params(ring_bits, ring_bits);  // Match RingOA domain
    // SharedOtParameters          shared_params(10);
    uint64_t                    d = ringoa_params.GetParameters().GetInputBitsize();

    AdditiveSharing2P             ass(d);
    ReplicatedSharing3P           rss(d);
    RingOaKeyGenerator            ringoa_gen(ringoa_params, ass);
    IntegerComparisonKeyGenerator ic_gen(ic_params, ass, ass);
    FileIo                        file_io;
    ShareIo                       sh_io;
    KeyIo                         key_io;

    // Generate keys
    std::array<RingOaKey, 3>                              ringoa_keys = ringoa_gen.GenerateKeys();
    std::pair<IntegerComparisonKey, IntegerComparisonKey> ic_keys     = ic_gen.GenerateKeys();

    // Save keys
    std::string key_path = kTestOSPath + "ringoakey_d" + ToString(d);
    key_io.SaveKey(key_path + "_0", ringoa_keys[0]);
    key_io.SaveKey(key_path + "_1", ringoa_keys[1]);
    key_io.SaveKey(key_path + "_2", ringoa_keys[2]);

    std::string db_path        = kTestOSPath + "ringoadb_d" + ToString(d);
    std::string idx_path       = kTestOSPath + "ringoaidx_d" + ToString(d);
    std::string expected_label = kTestOSPath + "pdte_expected_d" + ToString(d);
    std::string dcf_key_pref   = kTestOSPath + "pdte_dcf_key_";
    std::string dcf_trip_in    = kTestOSPath + "pdte_dcf";
    std::string dcf_trip_out   = kTestOSPath + "pdte_dcf_out";

    if ((1ULL << d) < kLayoutEntries) {
        throw std::runtime_error("OA domain too small for PDTE layout");
    }

    // 各ノード情報の初期設定
    std::vector<TreeNodePlain> tree(kNodeCount);
    uint64_t leaf_label_counter = 1;
    for (uint64_t i = 0; i < kNodeCount; ++i) {
        uint64_t left  = 2 * i + 1;
        uint64_t right = 2 * i + 2;
        bool     has_left = left < kNodeCount;
        bool     has_right = right < kNodeCount;
        tree[i].threshold  = 3 + (i % 4);
        tree[i].feature_id = i % kFeatureCount;
        tree[i].left       = has_left ? left : i;
        tree[i].right      = has_right ? right : i;
        tree[i].label      = (has_left || has_right) ? 0 : leaf_label_counter++;
        Logger::InfoLog(LOC, "[TreeGen] node[" + ToString(i) + "] thr=" + ToString(tree[i].threshold) + 
                        " fid=" + ToString(tree[i].feature_id) + " left=" + ToString(tree[i].left) + 
                        " right=" + ToString(tree[i].right) + " label=" + ToString(tree[i].label));
    }

    std::vector<uint64_t> features = BuildFeatureVector();
    for (size_t i = 0; i < features.size(); ++i) {
        Logger::InfoLog(LOC, "[TreeGen][Feature] idx=" + ToString(i) + " val=" + ToString(features[i]));
    }
    uint64_t expected = EvaluateTreePlain(tree, features);
    Logger::InfoLog(LOC, "[TreeGen] Expected result: " + ToString(expected));

    // ノード情報を1つの配列に詰め込む
    std::vector<uint64_t> database(1ULL << d, 0);
    for (uint64_t i = 0; i < kNodeCount; ++i) {
        database[kThresholdOffset + i]  = tree[i].threshold;
        database[kLeftOffset + i]       = tree[i].left;
        database[kRightOffset + i]      = tree[i].right;
        uint64_t fid = tree[i].feature_id % features.size();
        database[kFeatureValOffset + i] = features[fid];
        database[kLabelOffset + i]      = tree[i].label;
        if (i == 0 || i == 2 || i == 6 || i == 1022) {
            Logger::InfoLog(LOC, "[DBGen] node[" + ToString(i) + "] fid=" + ToString(fid) + " feature_val=" + ToString(features[fid]) + " stored_at=" + ToString(kFeatureValOffset + i));
        }
    }

    // 平文のノード情報をRSS化
    std::array<RepShareVec64, 3> database_sh = rss.ShareLocal(database);
    for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
        sh_io.SaveShare(db_path + "_" + ToString(p), database_sh[p]);
    }
    file_io.WriteBinary(db_path, database);

    // root(開始位置)のindexもRSS化
    uint64_t root_index = 0;
    std::array<RepShare64, 3> index_sh = rss.ShareLocal(root_index);
    file_io.WriteBinary(idx_path, root_index);
    for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
        sh_io.SaveShare(idx_path + "_" + ToString(p), index_sh[p]);
    }

    file_io.WriteBinary(expected_label, expected);

    SaveIntegerComparisonKey(dcf_key_pref + "0", ic_keys.first);
    SaveIntegerComparisonKey(dcf_key_pref + "1", ic_keys.second);

    // DCF用のbeaver triples生成
    AdditiveSharing2P dcf_in(ic_params.GetInputBitsize());
    AdditiveSharing2P dcf_out(ic_params.GetOutputBitsize());
    const uint64_t triple_budget =
        std::max<uint64_t>(1ULL << 22, ic_params.GetInputBitsize() * static_cast<uint64_t>(kTreeDepth) * 4096ULL);
    dcf_in.OfflineSetUp(triple_budget, dcf_trip_in);
    dcf_out.OfflineSetUp(triple_budget, dcf_trip_out);

    const uint32_t offline_queries = static_cast<uint32_t>(kTreeDepth * 16);
    // RingOA・RSS用のbeaver triples等生成
    ringoa_gen.OfflineSetUp(offline_queries, kTestOSPath);
    rss.OfflineSetUp(kTestOSPath + "prf");
    Logger::DebugLog(LOC, "Pdte_Offline_Test - Passed");
}

void Pdte_Online_Test(const osuCrypto::CLP &cmd) {
    Logger::SetPrintLog(true);
    Logger::InfoLog(LOC, "Pdte_Additive_Online_Test...");
    const bool debug_mode = cmd.isSet("debug") || cmd.isSet("-debug");
    std::vector<RingOaParameters> params_list = {
        RingOaParameters(kRingBits),
        // RingOaParameters(15),
        // RingOaParameters(20),
    };
    for (const auto &params : params_list) {
        params.PrintParameters();
        uint64_t d  = params.GetParameters().GetInputBitsize();
        IntegerComparisonParameters ic_params(d, d);  // 出力サイズをdにすると上手くいく
        uint64_t nu = params.GetParameters().GetTerminateBitsize();
        FileIo   file_io;
        ShareIo  sh_io;

        uint64_t              result{0};
        std::string           key_path      = kTestOSPath + "ringoakey_d" + ToString(d);
        std::string           db_path       = kTestOSPath + "ringoadb_d" + ToString(d);
        std::string           idx_path      = kTestOSPath + "ringoaidx_d" + ToString(d);
        std::string           expected_path = kTestOSPath + "pdte_expected_d" + ToString(d);
        std::string           dcf_key_pref  = kTestOSPath + "pdte_dcf_key_";
        std::string           dcf_trip_in   = kTestOSPath + "pdte_dcf";
        std::string           dcf_trip_out  = kTestOSPath + "pdte_dcf_out";
        std::vector<uint64_t> database;
        uint64_t              index{0};
        uint64_t              expected_label{0};
        file_io.ReadBinary(db_path, database);
        file_io.ReadBinary(idx_path, index);
        file_io.ReadBinary(expected_path, expected_label);
        
        // // Reconstruct tree and features for verification
        // std::vector<TreeNodePlain> tree(kNodeCount);
        // std::vector<uint64_t>      features(kFeatureCount);
        // for (uint64_t i = 0; i < kNodeCount; ++i) {
        //     tree[i].threshold  = database[kThresholdOffset + i];
        //     tree[i].left       = database[kLeftOffset + i];
        //     tree[i].right      = database[kRightOffset + i];
        //     tree[i].feature_id = i % kFeatureCount;
        //     tree[i].label      = database[kLabelOffset + i];
        //     if (i < kFeatureCount) {
        //         features[i] = database[kFeatureValOffset + i];
        //     }
        //     if (i == 0 || i == 2 || i == 6 || i == 1022) {
        //         Logger::InfoLog(LOC, "[DBRead] node[" + ToString(i) + "] fid=" + ToString(tree[i].feature_id) + " feature_val_from_db=" + ToString(database[kFeatureValOffset + i]));
        //     }
        // }
        // for (size_t i = 0; i < features.size(); ++i) {
        //     Logger::InfoLog(LOC, "[OnlineVerify][Feature] idx=" + ToString(i) + " val=" + ToString(features[i]));
        // }
        // uint64_t recalc_expected = EvaluateTreePlain(tree, features);
        // Logger::InfoLog(LOC, "[OnlineVerify] Recalculated expected: " + ToString(recalc_expected) + 
        //                 ", stored expected: " + ToString(expected_label));

        // オフラインテストを必ず実行する想定で不要
        // const uint64_t triple_budget =
        //     std::max<uint64_t>(1ULL << 22, ic_params.GetInputBitsize() * static_cast<uint64_t>(kTreeDepth) * 4096ULL);
        // {
        //     AdditiveSharing2P dcf_in_offline(ic_params.GetInputBitsize());
        //     AdditiveSharing2P dcf_out_offline(ic_params.GetOutputBitsize());
        //     dcf_in_offline.OfflineSetUp(triple_budget, dcf_trip_in);
        //     dcf_out_offline.OfflineSetUp(triple_budget, dcf_trip_out);
        // }
        // {
        //     AdditiveSharing2P ass_tmp(d);
        //     RingOaKeyGenerator ringoa_tmp(params, ass_tmp);
        //     const uint32_t offline_queries = static_cast<uint32_t>(kTreeDepth * 16);
        //     ringoa_tmp.OfflineSetUp(offline_queries, kTestOSPath);
        // }

        // Define the task for each party
        auto MakeTask = [&](int party_id) {
            return [=, &result](osuCrypto::Channel &chl_next, osuCrypto::Channel &chl_prev) {
                ringoa::GlobalRng::Initialize();
                ReplicatedSharing3P rss(d);
                AdditiveSharing2P   ass_prev(d);
                AdditiveSharing2P   ass_next(d);
                RingOaEvaluator     eval(params, rss, ass_prev, ass_next);
                Channels            chls(party_id, chl_prev, chl_next);

                // Load keys
                RingOaKey key(party_id, params);
                KeyIo     key_io;
                key_io.LoadKey(key_path + "_" + ToString(party_id), key);

                // Load data
                RepShareVec64 database_sh;
                RepShare64    index_sh;
                sh_io.LoadShare(db_path + "_" + ToString(party_id), database_sh);
                sh_io.LoadShare(idx_path + "_" + ToString(party_id), index_sh);
                RepShareView64 db_view(database_sh);

                std::vector<ringoa::block> uv_prev(1U << nu), uv_next(1U << nu);

                // Setup the PRF keys
                eval.OnlineSetUp(party_id, kTestOSPath);
                rss.OnlineSetUp(party_id, kTestOSPath + "prf");

                std::unique_ptr<AdditiveSharing2P>           dcf_in;
                std::unique_ptr<AdditiveSharing2P>           dcf_out;
                std::unique_ptr<IntegerComparisonEvaluator> dcf_eval;
                std::unique_ptr<IntegerComparisonKey>       dcf_key;
                if (party_id < 2) {
                    dcf_in  = std::make_unique<AdditiveSharing2P>(ic_params.GetInputBitsize());
                    dcf_out = std::make_unique<AdditiveSharing2P>(ic_params.GetOutputBitsize());
                    dcf_key = std::make_unique<IntegerComparisonKey>(party_id, ic_params);
                    LoadIntegerComparisonKey(dcf_key_pref + ToString(party_id), *dcf_key);
                    dcf_in->OnlineSetUp(party_id, dcf_trip_in);
                    dcf_out->OnlineSetUp(party_id, dcf_trip_out);
                    dcf_eval = std::make_unique<IntegerComparisonEvaluator>(ic_params, *dcf_in, *dcf_out);
                }

                // 公開値を、replicated share として表現するための関数
                auto MakePublicShare = [&](uint64_t value) {
                    RepShare64 sh;
                    uint64_t   masked = Mod2N(value, d);
                    if (party_id == 0) {
                        sh[0] = masked;
                        sh[1] = 0;
                    } else if (party_id == 1) {
                        sh[0] = 0;
                        sh[1] = masked;
                    } else {
                        sh[0] = 0;
                        sh[1] = 0;
                    }
                    return sh;
                };

                auto AddConstIdx = [&](const RepShare64 &idx, uint64_t offset, RepShare64 &out) {
                    RepShare64 off = MakePublicShare(offset);
                    rss.EvaluateAdd(idx, off, out);
                };

                auto ObliviousRead = [&](const RepShare64 &idx, RepShare64 &out) {
                    eval.Evaluate(chls, key, uv_prev, uv_next, db_view, idx, out);
                };

                const uint64_t dcf_in_bits  = ic_params.GetInputBitsize();
                const uint64_t dcf_out_bits = ic_params.GetOutputBitsize();
                auto MaskValue = [](uint64_t value, uint64_t bits) -> uint64_t {
                    if (bits >= 64)
                        return value;
                    uint64_t mask = (bits == 64) ? std::numeric_limits<uint64_t>::max() : ((1ULL << bits) - 1ULL);
                    return value & mask;
                };
                auto ConvertReplicatedToAdditive = [&](const RepShare64 &sh, uint64_t &out) {
                    if (party_id == 2) {
                        uint64_t r = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_in_bits);

                        // P2 は (x2, x0) を持ってる想定なので sh[0] を x2 として使う
                        uint64_t x2 = Mod2N(sh[0], dcf_in_bits);
                        uint64_t masked = Mod2N(x2 - r, dcf_in_bits);

                        chls.next.send(r);        // to P0
                        chls.prev.send(masked);   // to P1
                        out = 0;
                    } else if (party_id == 0) {
                        uint64_t r = 0;
                        chls.prev.recv(r);        // from P2
                        out = Mod2N(sh[0] + r, dcf_in_bits);  // P0 の sh[0] は x0
                    } else { // party_id == 1
                        uint64_t masked = 0;
                        chls.next.recv(masked);   // from P2
                        out = Mod2N(sh[0] + masked, dcf_in_bits); // P1 の sh[0] は x1
                    }
                };

                auto ConvertSsBitToReplicated = [&](uint64_t local_share, RepShare64 &bit_sh) {
                    if (party_id == 0) {
                        uint64_t s0 = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_out_bits);
                        chls.next.send(s0);                                   // to P1
                        uint64_t masked = Mod2N(local_share - s0, dcf_out_bits);
                        chls.prev.send(masked);                               // to P2
                        uint64_t s2 = 0;
                        chls.prev.recv(s2);                                   // from P2
                        bit_sh[0] = Mod2N(s0, d);
                        bit_sh[1] = Mod2N(s2, d);
                        // if (debug_mode) Logger::InfoLog(LOC, "[ConvS2R] P0: local=" + ToString(local_share) + " s0=" + ToString(s0) + " masked=" + ToString(masked) + " s2=" + ToString(s2) + " bit_sh=(" + ToString(bit_sh[0]) + "," + ToString(bit_sh[1]) + ")");
                    } else if (party_id == 1) {
                        uint64_t s0 = 0;
                        chls.prev.recv(s0);                                   // from P0
                        uint64_t s1 = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_out_bits);
                        chls.next.send(s1);                                   // to P2
                        uint64_t masked = Mod2N(local_share - s1, dcf_out_bits);
                        chls.next.send(masked);                               // to P2
                        bit_sh[0] = Mod2N(s1, d);
                        bit_sh[1] = Mod2N(s0, d);
                        // if (debug_mode) Logger::InfoLog(LOC, "[ConvS2R] P1: local=" + ToString(local_share) + " s0=" + ToString(s0) + " s1=" + ToString(s1) + " masked=" + ToString(masked) + " bit_sh=(" + ToString(bit_sh[0]) + "," + ToString(bit_sh[1]) + ")");
                    } else {
                        uint64_t s1 = 0;
                        chls.prev.recv(s1);                                   // from P1
                        uint64_t masked_from_p0 = 0;
                        chls.next.recv(masked_from_p0);                       // from P0
                        uint64_t masked_from_p1 = 0;
                        chls.prev.recv(masked_from_p1);                       // from P1
                        uint64_t s2 = Mod2N(masked_from_p0 + masked_from_p1, dcf_out_bits);
                        chls.next.send(s2);                                   // to P0
                        bit_sh[0] = Mod2N(s2, d);
                        bit_sh[1] = Mod2N(s1, d);
                        // if (debug_mode) Logger::InfoLog(LOC, "[ConvS2R] P2: s1=" + ToString(s1) + " masked_p0=" + ToString(masked_from_p0) + " masked_p1=" + ToString(masked_from_p1) + " s2=" + ToString(s2) + " bit_sh=(" + ToString(bit_sh[0]) + "," + ToString(bit_sh[1]) + ")");
                    }
                };

                auto ShareStr = [&](const RepShare64 &share) {
                    return "(" + ToString(share[0]) + ", " + ToString(share[1]) + ")";
                };

                RepShare64 current_idx = index_sh;
                RepShare64 label_share;

                for (uint32_t depth = 0; depth < kTreeDepth; ++depth) {
                    RepShare64 thr_idx, left_idx, right_idx, fid_idx;
                    RepShare64 thr_sh, left_sh, right_sh, fid_sh;

                    AddConstIdx(current_idx, kThresholdOffset, thr_idx);
                    ObliviousRead(thr_idx, thr_sh);

                    AddConstIdx(current_idx, kLeftOffset, left_idx);
                    ObliviousRead(left_idx, left_sh);

                    AddConstIdx(current_idx, kRightOffset, right_idx);
                    ObliviousRead(right_idx, right_sh);

                    RepShare64 feature_val_idx;
                    AddConstIdx(current_idx, kFeatureValOffset, feature_val_idx);
                    RepShare64 feature_val;
                    ObliviousRead(feature_val_idx, feature_val);

                    RepShare64 delta_sh;
                    rss.EvaluateSub(feature_val, thr_sh, delta_sh);

                    RepShare64 cmp_bit;
                    uint64_t delta_part  = 0;
                    uint64_t delta_plain = 0;
                    uint64_t idx_plain   = 0;
                    uint64_t thr_plain   = 0;
                    uint64_t feat_plain  = 0;
                    // if (debug_mode) {
                    //     rss.Open(chls, current_idx, idx_plain);
                    //     rss.Open(chls, thr_sh, thr_plain);
                    //     rss.Open(chls, feature_val, feat_plain);
                    // }
                    ConvertReplicatedToAdditive(delta_sh, delta_part);
                    // if (debug_mode) {
                    //     rss.Open(chls, delta_sh, delta_plain);
                    // }
                    // std::string delta_log = "[Pdte][depth " + ToString(depth) + "] idx=" + ShareStr(current_idx) +
                    //                         " thr=" + ShareStr(thr_sh) + " feature=" + ShareStr(feature_val) +
                    //                         " delta_part=" + ToString(delta_part);
                    // if (debug_mode)
                    //     delta_log += " delta_plain=" + ToString(delta_plain) + " idx_plain=" + ToString(idx_plain) +
                    //                  " thr_plain=" + ToString(thr_plain) + " feat_plain=" + ToString(feat_plain);
                    // Logger::InfoLog(LOC, delta_log);

                    if (party_id < 2) {
                        osuCrypto::Channel &dcf_chl = (party_id == 0) ? chls.next : chls.prev;
                        uint64_t              bit_share = dcf_eval->EvaluateSharedInput(dcf_chl, *dcf_key, delta_part, 0);
                        // Library returns 1 when delta >= 0, so invert to obtain (feature < threshold).
                        // if (debug_mode)
                        //     Logger::InfoLog(LOC, "[DCF] P" + ToString(party_id) + ": delta_part=" + ToString(delta_part) +
                        //                             " bit_share=" + ToString(bit_share));
                        ConvertSsBitToReplicated(bit_share, cmp_bit);
                    } else {
                        // if (debug_mode)
                        //     Logger::InfoLog(LOC, "[DCF] P2: not participating in DCF");
                        ConvertSsBitToReplicated(0, cmp_bit);
                    }
                    RepShare64 one_sh = MakePublicShare(1);
                    RepShare64 cmp_lt;
                    rss.EvaluateSub(one_sh, cmp_bit, cmp_lt);
                    cmp_bit = cmp_lt;
                    // if (debug_mode)
                    //     Logger::InfoLog(LOC, "[DCF] inverted cmp_bit -> " + ShareStr(cmp_bit));

                    RepShare64 next_idx;
                    rss.EvaluateSelect(chls, right_sh, left_sh, cmp_bit, next_idx);
                    uint64_t cmp_plain = 0;
                    uint64_t next_plain = 0;
                    // if (debug_mode) {
                    //     rss.Open(chls, cmp_bit, cmp_plain);
                    //     rss.Open(chls, next_idx, next_plain);
                    // }
                    // std::string cmp_log = "[Pdte][depth " + ToString(depth) + "] cmp_bit=" + ShareStr(cmp_bit) +
                    //                       " left=" + ShareStr(left_sh) + " right=" + ShareStr(right_sh) + " next_idx=" + ShareStr(next_idx);
                    // if (debug_mode)
                    //     cmp_log += " cmp_plain=" + ToString(cmp_plain) + " next_plain=" + ToString(next_plain);
                    // Logger::InfoLog(LOC, cmp_log);
                    current_idx = next_idx;
                }

                RepShare64 label_idx;
                AddConstIdx(current_idx, kLabelOffset, label_idx);
                uint64_t final_idx_plain = 0;
                uint64_t label_idx_plain = 0;
                // if (debug_mode) {
                //     rss.Open(chls, current_idx, final_idx_plain);
                //     rss.Open(chls, label_idx, label_idx_plain);
                // }
                ObliviousRead(label_idx, label_share);
                uint64_t final_plain = 0;
                // if (debug_mode) {
                //     rss.Open(chls, label_share, final_plain);
                // }
                // std::string final_log = "[Pdte] final current_idx=" + ShareStr(current_idx) + 
                //                        " label_idx=" + ShareStr(label_idx) + " label_share=" + ShareStr(label_share);
                // if (debug_mode)
                //     final_log += " final_idx_plain=" + ToString(final_idx_plain) + 
                //                 " label_idx_plain=" + ToString(label_idx_plain) + " label_plain=" + ToString(final_plain);
                // Logger::InfoLog(LOC, final_log);

                uint64_t local_res = 0;
                rss.Open(chls, label_share, local_res);
                result = local_res;
            };
        };

        // Create tasks for each party
        auto task_p0 = MakeTask(0);
        auto task_p1 = MakeTask(1);
        auto task_p2 = MakeTask(2);

        ThreePartyNetworkManager net_mgr;
        // Configure network based on party ID and wait for completion
        int party_id = cmd.isSet("party") ? cmd.get<int>("party") : -1;
        net_mgr.AutoConfigure(party_id, task_p0, task_p1, task_p2);
        net_mgr.WaitForCompletion();

        Logger::DebugLog(LOC, "Result: " + ToString(result));

        if (result != expected_label)
            throw osuCrypto::UnitTestFail("Pdte_Online_Test failed: result = " + ToString(result) +
                                          ", expected = " + ToString(expected_label));
    }
    Logger::DebugLog(LOC, "Pdte_Online_Test - Passed");
}

}    // namespace test_ringoa
