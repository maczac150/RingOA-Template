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
#include <RingOA/sharing/share_config.h>
#include <RingOA/sharing/share_io.h>
#include <RingOA/utils/logger.h>
#include <RingOA/utils/network.h>
#include <RingOA/utils/timer.h>
#include <RingOA/utils/to_string.h>
#include <RingOA/utils/utils.h>
#include <RingOA/utils/rng.h>

namespace {

const std::string kCurrentPath = ringoa::GetCurrentDirectory();
const std::string kTestOSPath  = kCurrentPath + "/data/test/";
const std::string kBenchRingOAPath = kCurrentPath + "/data/bench/ringoa/";
const std::string kLogRingOaPath = kCurrentPath + "/data/logs/ringoa/";

}    // namespace

namespace test_ringoa {

using ringoa::Channels;
using ringoa::FileIo;
using ringoa::Logger;
using ringoa::Mod2N;
using ringoa::ThreePartyNetworkManager;
using ringoa::TimerManager;
using ringoa::ToString, ringoa::Format;
using ringoa::fss::EvalType;
using ringoa::proto::IntegerComparisonConfig;
using ringoa::proto::IntegerComparisonEvaluator;
using ringoa::proto::IntegerComparisonKey;
using ringoa::proto::IntegerComparisonKeyGenerator;
using ringoa::proto::IntegerComparisonParameters;
using ringoa::proto::KeyIo;
using ringoa::proto::ProtocolContext2P;
using ringoa::proto::ProtocolContext3P;
using ringoa::proto::RingOaConfig;
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
using ringoa::sharing::ShareConfig;
using ringoa::sharing::ShareIo;

namespace {

constexpr uint32_t kTreeDepth    = 17;
constexpr uint64_t kNodeCount    = 1ULL << kTreeDepth;
constexpr uint64_t kFeatureCount = 4;
constexpr uint32_t kRingBits     = 20;

constexpr uint64_t kBenchRepeatDefault = 5;
constexpr uint32_t kBenchTreeDepth    = 10;
constexpr uint64_t kBenchNodeCount    = 1ULL << kBenchTreeDepth;
constexpr uint64_t kBenchFeatureCount = 4;
constexpr uint32_t kBenchRingBits     = 33;
constexpr uint32_t kBenchDbBits       = kBenchTreeDepth + 3;

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

std::vector<uint64_t> BuildBenchFeatureVector() {
    std::vector<uint64_t> features(kBenchFeatureCount, 0);
    if (kBenchFeatureCount == 0)
        return features;

    uint64_t prev = 1;
    uint64_t curr = 2;
    features[0]   = prev;
    for (uint64_t i = 1; i < kBenchFeatureCount; ++i) {
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

constexpr uint64_t kBenchThresholdOffset  = 0;
constexpr uint64_t kBenchLeftOffset       = kBenchThresholdOffset + kBenchNodeCount;
constexpr uint64_t kBenchRightOffset      = kBenchLeftOffset + kBenchNodeCount;
constexpr uint64_t kBenchFeatureValOffset = kBenchRightOffset + kBenchNodeCount;
constexpr uint64_t kBenchLabelOffset      = kBenchFeatureValOffset + kBenchNodeCount;
constexpr uint64_t kBenchLayoutEntries    = kBenchLabelOffset + kBenchNodeCount;

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
    // Logger::InfoLog(LOC, "[PlainEval] Starting with idx=" + ToString(idx));
    for (uint32_t depth = 0; depth < kTreeDepth; ++depth) {
        const auto &node = tree[idx];
        uint64_t     fid = node.feature_id % features.size();
        uint64_t     fv  = features[fid];
        bool         cmp = (fv < node.threshold);
        uint64_t     next_idx = cmp ? node.left : node.right;
        // Logger::InfoLog(LOC, "[PlainEval][depth " + ToString(depth) + "] idx=" + ToString(idx) + 
        //                 " fid=" + ToString(fid) + " fv=" + ToString(fv) + " thr=" + ToString(node.threshold) + 
        //                 " cmp=" + ToString(cmp) + " left=" + ToString(node.left) + " right=" + ToString(node.right) + 
        //                 " next_idx=" + ToString(next_idx) + " label=" + ToString(node.label));
        idx = next_idx;
        if (idx >= tree.size()) {
            // Logger::InfoLog(LOC, "[PlainEval] idx >= tree.size(), clamping to " + ToString(tree.size() - 1));
            idx = tree.size() - 1;
        }
    }
    Logger::InfoLog(LOC, "[PlainEval] Final idx=" + ToString(idx) + " label=" + ToString(tree[idx].label));
    return tree[idx].label;
}

uint64_t EvaluateBenchTreePlain(const std::vector<TreeNodePlain> &tree, const std::vector<uint64_t> &features) {
    uint64_t idx = 0;
    for (uint32_t depth = 0; depth < kBenchTreeDepth; ++depth) {
        const auto &node = tree[idx];
        uint64_t     fid = node.feature_id % features.size();
        uint64_t     fv  = features[fid];
        bool         cmp = (fv < node.threshold);
        uint64_t     next_idx = cmp ? node.left : node.right;
        idx = next_idx;
        if (idx >= tree.size())
            idx = tree.size() - 1;
    }
    return tree[idx].label;
}

uint64_t EvaluateTreePlainDepth(const std::vector<TreeNodePlain> &tree,
                                const std::vector<uint64_t> &features,
                                uint32_t depth_max) {
    uint64_t idx = 0;
    for (uint32_t depth = 0; depth < depth_max; ++depth) {
        const auto &node = tree[idx];
        uint64_t     fid = node.feature_id % features.size();
        uint64_t     fv  = features[fid];
        bool         cmp = (fv < node.threshold);
        uint64_t     next_idx = cmp ? node.left : node.right;
        idx = next_idx;
        if (idx >= tree.size())
            idx = tree.size() - 1;
    }
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

    ShareConfig      share_config = ShareConfig::Custom(kRingBits);
    RingOaParameters ringoa_params(RingOaConfig(kRingBits), share_config);
    uint64_t         ring_bits = ringoa_params.GetParameters().GetInputBitsize();
    IntegerComparisonConfig ic_cfg;
    ic_cfg.input_domain_bits = ring_bits;
    IntegerComparisonParameters ic_params(ic_cfg, share_config);  // Match RingOA domain
    // SharedOtParameters          shared_params(10);
    uint64_t                    d = ringoa_params.GetParameters().GetInputBitsize();

    ProtocolContext3P             ringoa_ctx(share_config);
    ProtocolContext2P             ic_ctx(share_config);
    auto                         &rss = ringoa_ctx.Rss();
    RingOaKeyGenerator            ringoa_gen(ringoa_params, ringoa_ctx);
    IntegerComparisonKeyGenerator ic_gen(ic_params, ic_ctx);
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
        // Logger::InfoLog(LOC, "[TreeGen] node[" + ToString(i) + "] thr=" + ToString(tree[i].threshold) + 
        //                 " fid=" + ToString(tree[i].feature_id) + " left=" + ToString(tree[i].left) + 
        //                 " right=" + ToString(tree[i].right) + " label=" + ToString(tree[i].label));
    }

    std::vector<uint64_t> features = BuildFeatureVector();
    // for (size_t i = 0; i < features.size(); ++i) {
    //     Logger::InfoLog(LOC, "[TreeGen][Feature] idx=" + ToString(i) + " val=" + ToString(features[i]));
    // }
    uint64_t expected = EvaluateTreePlain(tree, features);
    // Logger::InfoLog(LOC, "[TreeGen] Expected result: " + ToString(expected));

    // ノード情報を1つの配列に詰め込む
    std::vector<uint64_t> database(1ULL << d, 0);
    for (uint64_t i = 0; i < kNodeCount; ++i) {
        database[kThresholdOffset + i]  = tree[i].threshold;
        database[kLeftOffset + i]       = tree[i].left;
        database[kRightOffset + i]      = tree[i].right;
        uint64_t fid = tree[i].feature_id % features.size();
        database[kFeatureValOffset + i] = features[fid];
        database[kLabelOffset + i]      = tree[i].label;
        // if (i == 0 || i == 2 || i == 6 || i == 1022) {
        //     Logger::InfoLog(LOC, "[DBGen] node[" + ToString(i) + "] fid=" + ToString(fid) + " feature_val=" + ToString(features[fid]) + " stored_at=" + ToString(kFeatureValOffset + i));
        // }
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
    auto &dcf_share = ic_ctx.Arith();
    const uint64_t triple_budget =
        std::max<uint64_t>(1ULL << 22, ic_params.GetInputDomainBits() * static_cast<uint64_t>(kTreeDepth) * 4096ULL);
    dcf_share.OfflineSetUp(triple_budget, dcf_trip_in);

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
        RingOaParameters(RingOaConfig(kRingBits), ShareConfig::Custom(kRingBits)),
        // RingOaParameters(15),
        // RingOaParameters(20),
    };
    for (const auto &params : params_list) {
        params.PrintParametersDebug();
        uint64_t d  = params.GetParameters().GetInputBitsize();
        ShareConfig share_config = ShareConfig::Custom(params.GetShareSize());
        IntegerComparisonConfig ic_cfg;
        ic_cfg.input_domain_bits = d;
        IntegerComparisonParameters ic_params(ic_cfg, share_config);  // 出力サイズをdにすると上手くいく
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
                ProtocolContext3P ringoa_ctx(share_config);
                ProtocolContext2P ic_ctx(share_config);
                auto             &rss = ringoa_ctx.Rss();
                RingOaEvaluator   eval(params, ringoa_ctx);
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

                std::unique_ptr<IntegerComparisonEvaluator> dcf_eval;
                std::unique_ptr<IntegerComparisonKey>       dcf_key;
                if (party_id < 2) {
                    dcf_key = std::make_unique<IntegerComparisonKey>(party_id, ic_params);
                    LoadIntegerComparisonKey(dcf_key_pref + ToString(party_id), *dcf_key);
                    ic_ctx.Arith().OnlineSetUp(party_id, dcf_trip_in);
                    dcf_eval = std::make_unique<IntegerComparisonEvaluator>(ic_params, ic_ctx);
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

                const uint64_t dcf_in_bits  = ic_params.GetInputDomainBits();
                const uint64_t dcf_out_bits = ic_params.GetDdcfOutputBitsize();
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

void Pdte_Offline_Bench(const osuCrypto::CLP &cmd) {
    Logger::InfoLog(LOC, "Pdte_Offline_Bench...");
    TimerManager timer_mgr;
    uint64_t repeat = cmd.getOr("bench_repeat", kBenchRepeatDefault);
    uint32_t bench_tree_depth = cmd.getOr("bench_depth", static_cast<int>(kBenchTreeDepth));
    uint32_t bench_dbits = cmd.getOr("bench_dbits", static_cast<int>(kBenchDbBits));
    uint32_t bench_ringbits = cmd.getOr("bench_ringbits", static_cast<int>(kBenchRingBits));
    bool     use_external_db = cmd.hasValue("bench_db");

    if (use_external_db && !cmd.hasValue("bench_depth")) {
        throw std::runtime_error("bench_db requires --bench_depth to match the packed tree depth");
    }

    ShareConfig      share_config = ShareConfig::Custom(bench_ringbits);
    RingOaParameters ringoa_params(RingOaConfig(bench_dbits), share_config);
    uint64_t         ring_bits = ringoa_params.GetParameters().GetInputBitsize();
    IntegerComparisonConfig ic_cfg;
    ic_cfg.input_domain_bits = ring_bits;
    IntegerComparisonParameters ic_params(ic_cfg, share_config);
    uint64_t                    d = ringoa_params.GetParameters().GetInputBitsize();

    ProtocolContext3P             ringoa_ctx(share_config);
    ProtocolContext2P             ic_ctx(share_config);
    auto                         &rss = ringoa_ctx.Rss();
    RingOaKeyGenerator            ringoa_gen(ringoa_params, ringoa_ctx);
    IntegerComparisonKeyGenerator ic_gen(ic_params, ic_ctx);
    FileIo                        file_io;
    ShareIo                       sh_io;
    KeyIo                         key_io;

    std::string key_path = kBenchRingOAPath + "ringoakey_d" + ToString(d);
    std::string db_path        = kBenchRingOAPath + "ringoadb_d" + ToString(d);
    std::string idx_path       = kBenchRingOAPath + "ringoaidx_d" + ToString(d);
    std::string expected_label = kBenchRingOAPath + "pdte_expected_d" + ToString(d);
    std::string dcf_key_pref   = kBenchRingOAPath + "pdte_dcf_key_";
    std::string dcf_trip_in    = kBenchRingOAPath + "pdte_dcf";

    uint64_t bench_node_count = 1ULL << bench_tree_depth;
    uint64_t bench_threshold_offset  = 0;
    uint64_t bench_left_offset       = bench_threshold_offset + bench_node_count;
    uint64_t bench_right_offset      = bench_left_offset + bench_node_count;
    uint64_t bench_feature_val_offset = bench_right_offset + bench_node_count;
    uint64_t bench_label_offset      = bench_feature_val_offset + bench_node_count;
    uint64_t bench_layout_entries    = bench_label_offset + bench_node_count;

    if ((1ULL << d) < bench_layout_entries) {
        throw std::runtime_error("OA domain too small for PDTE layout");
    }

    int32_t timer_keygen = timer_mgr.CreateNewTimer("KeyGen");
    int32_t timer_datagen = timer_mgr.CreateNewTimer("DataGen");
    int32_t timer_offline = timer_mgr.CreateNewTimer("OfflineSetUp");

    timer_mgr.SelectTimer(timer_keygen);
    timer_mgr.Start();
    std::array<RingOaKey, 3>                              ringoa_keys = ringoa_gen.GenerateKeys();
    std::pair<IntegerComparisonKey, IntegerComparisonKey> ic_keys     = ic_gen.GenerateKeys();
    timer_mgr.Stop("d=" + ToString(d));

    key_io.SaveKey(key_path + "_0", ringoa_keys[0]);
    key_io.SaveKey(key_path + "_1", ringoa_keys[1]);
    key_io.SaveKey(key_path + "_2", ringoa_keys[2]);
    SaveIntegerComparisonKey(dcf_key_pref + "0", ic_keys.first);
    SaveIntegerComparisonKey(dcf_key_pref + "1", ic_keys.second);

    timer_mgr.SelectTimer(timer_datagen);
    timer_mgr.Start();
    std::vector<uint64_t> database;
    uint64_t expected = 0;
    if (use_external_db) {
        if (!cmd.hasValue("bench_expected")) {
            throw std::runtime_error("bench_db requires --bench_expected for expected label");
        }
        std::string ext_db_path = cmd.get<std::string>("bench_db");
        std::string ext_expected_path = cmd.get<std::string>("bench_expected");
        file_io.ReadBinary(ext_db_path, database);
        file_io.ReadBinary(ext_expected_path, expected);
        if (database.size() != (1ULL << d)) {
            throw std::runtime_error("bench_db size does not match --bench_dbits (2^d)");
        }
    } else {
        std::vector<TreeNodePlain> tree(bench_node_count);
        uint64_t leaf_label_counter = 1;
        for (uint64_t i = 0; i < bench_node_count; ++i) {
            uint64_t left  = 2 * i + 1;
            uint64_t right = 2 * i + 2;
            bool     has_left = left < bench_node_count;
            bool     has_right = right < bench_node_count;
            tree[i].threshold  = 3 + (i % 4);
            tree[i].feature_id = i % kBenchFeatureCount;
            tree[i].left       = has_left ? left : i;
            tree[i].right      = has_right ? right : i;
            tree[i].label      = (has_left || has_right) ? 0 : leaf_label_counter++;
        }

        std::vector<uint64_t> features = BuildBenchFeatureVector();
        expected = EvaluateTreePlainDepth(tree, features, bench_tree_depth);

        database.assign(1ULL << d, 0);
        for (uint64_t i = 0; i < bench_node_count; ++i) {
            database[bench_threshold_offset + i]  = tree[i].threshold;
            database[bench_left_offset + i]       = tree[i].left;
            database[bench_right_offset + i]      = tree[i].right;
            uint64_t fid = tree[i].feature_id % features.size();
            database[bench_feature_val_offset + i] = features[fid];
            database[bench_label_offset + i]      = tree[i].label;
        }
    }

    std::array<RepShareVec64, 3> database_sh = rss.ShareLocal(database);
    for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
        sh_io.SaveShare(db_path + "_" + ToString(p), database_sh[p]);
    }
    file_io.WriteBinary(db_path, database);

    uint64_t root_index = 0;
    std::array<RepShare64, 3> index_sh = rss.ShareLocal(root_index);
    file_io.WriteBinary(idx_path, root_index);
    for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
        sh_io.SaveShare(idx_path + "_" + ToString(p), index_sh[p]);
    }
    file_io.WriteBinary(expected_label, expected);
    timer_mgr.Stop("d=" + ToString(d));

    timer_mgr.SelectTimer(timer_offline);
    timer_mgr.Start();
    auto &dcf_share = ic_ctx.Arith();
    const uint64_t base_budget =
        std::max<uint64_t>(1ULL << 22, ic_params.GetInputDomainBits() * static_cast<uint64_t>(bench_tree_depth) * 4096ULL);
    const uint64_t triple_budget = base_budget * repeat;
    dcf_share.OfflineSetUp(triple_budget, dcf_trip_in);

    const uint32_t offline_queries =
        static_cast<uint32_t>(bench_tree_depth * 16 * repeat);
    ringoa_gen.OfflineSetUp(offline_queries, kBenchRingOAPath);
    rss.OfflineSetUp(kBenchRingOAPath + "prf");
    timer_mgr.Stop("d=" + ToString(d));

    timer_mgr.PrintCurrentResults("d=" + ToString(d), ringoa::TimeUnit::MILLISECONDS, true);
    Logger::InfoLog(LOC, "Pdte_Offline_Bench - Completed");
    Logger::ExportLogListAndClear(kLogRingOaPath + "pdte_offline_bench", true);
}

void Pdte_Online_Bench(const osuCrypto::CLP &cmd) {
    Logger::SetPrintLog(true);
    Logger::InfoLog(LOC, "Pdte_Online_Bench...");
    uint64_t repeat = cmd.getOr("bench_repeat", kBenchRepeatDefault);
    uint32_t bench_tree_depth = cmd.getOr("bench_depth", static_cast<int>(kBenchTreeDepth));
    uint32_t bench_dbits = cmd.getOr("bench_dbits", static_cast<int>(kBenchDbBits));
    uint32_t bench_ringbits = cmd.getOr("bench_ringbits", static_cast<int>(kBenchRingBits));
    int party_id = cmd.isSet("party") ? cmd.get<int>("party") : -1;
    std::string network = cmd.isSet("network") ? cmd.get<std::string>("network") : "";

    ShareConfig      share_config = ShareConfig::Custom(bench_ringbits);
    RingOaParameters params(RingOaConfig(bench_dbits), share_config);
    params.PrintParametersDebug();
    uint64_t d  = params.GetParameters().GetInputBitsize();
    IntegerComparisonConfig ic_cfg;
    ic_cfg.input_domain_bits = d;
    IntegerComparisonParameters ic_params(ic_cfg, share_config);
    uint64_t nu = params.GetParameters().GetTerminateBitsize();
    FileIo   file_io;
    ShareIo  sh_io;

    uint64_t              result{0};
    std::string           key_path      = kBenchRingOAPath + "ringoakey_d" + ToString(d);
    std::string           db_path       = kBenchRingOAPath + "ringoadb_d" + ToString(d);
    std::string           idx_path      = kBenchRingOAPath + "ringoaidx_d" + ToString(d);
    std::string           expected_path = kBenchRingOAPath + "pdte_expected_d" + ToString(d);
    std::string           dcf_key_pref  = kBenchRingOAPath + "pdte_dcf_key_";
    std::string           dcf_trip_in   = kBenchRingOAPath + "pdte_dcf";
    std::vector<uint64_t> database;
    uint64_t              index{0};
    uint64_t              expected_label{0};
    file_io.ReadBinary(db_path, database);
    file_io.ReadBinary(idx_path, index);
    file_io.ReadBinary(expected_path, expected_label);
    if (database.size() != (1ULL << d)) {
        throw std::runtime_error("bench database size does not match input bitsize");
    }

    uint64_t bench_node_count = 1ULL << bench_tree_depth;
    uint64_t bench_threshold_offset  = 0;
    uint64_t bench_left_offset       = bench_threshold_offset + bench_node_count;
    uint64_t bench_right_offset      = bench_left_offset + bench_node_count;
    uint64_t bench_feature_val_offset = bench_right_offset + bench_node_count;
    uint64_t bench_label_offset      = bench_feature_val_offset + bench_node_count;

    auto MakeTask = [&](int party_id) {
        return [=, &result](osuCrypto::Channel &chl_next, osuCrypto::Channel &chl_prev) {
            ringoa::GlobalRng::Initialize();
            TimerManager timer_mgr;
            int32_t timer_setup = timer_mgr.CreateNewTimer("OnlineSetUp P" + ToString(party_id));
            int32_t timer_eval = timer_mgr.CreateNewTimer("Eval P" + ToString(party_id));

            timer_mgr.SelectTimer(timer_setup);
            timer_mgr.Start();

            ProtocolContext3P ringoa_ctx(share_config);
            ProtocolContext2P ic_ctx(share_config);
            auto             &rss = ringoa_ctx.Rss();
            RingOaEvaluator   eval(params, ringoa_ctx);
            Channels            chls(party_id, chl_prev, chl_next);

            RingOaKey key(party_id, params);
            KeyIo     key_io;
            key_io.LoadKey(key_path + "_" + ToString(party_id), key);

            RepShareVec64 database_sh;
            RepShare64    index_sh;
            sh_io.LoadShare(db_path + "_" + ToString(party_id), database_sh);
            sh_io.LoadShare(idx_path + "_" + ToString(party_id), index_sh);
            RepShareView64 db_view(database_sh);

            std::vector<ringoa::block> uv_prev(1U << nu), uv_next(1U << nu);

            eval.OnlineSetUp(party_id, kBenchRingOAPath);
            rss.OnlineSetUp(party_id, kBenchRingOAPath + "prf");

            std::unique_ptr<IntegerComparisonEvaluator> dcf_eval;
            std::unique_ptr<IntegerComparisonKey>       dcf_key;
            if (party_id < 2) {
                dcf_key = std::make_unique<IntegerComparisonKey>(party_id, ic_params);
                LoadIntegerComparisonKey(dcf_key_pref + ToString(party_id), *dcf_key);
                ic_ctx.Arith().OnlineSetUp(party_id, dcf_trip_in);
                dcf_eval = std::make_unique<IntegerComparisonEvaluator>(ic_params, ic_ctx);
            }

            timer_mgr.Stop("d=" + ToString(d));

            // 公開値をRSSの形式で各パーティに配布するヘルパー関数
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

            // 共有されたidxに公開値offsetを加算するヘルパー関数
            // ノード情報は下記の形式で一本の配列で保持。
            // database = [ threshold | left | right | feature_val | label ]
            // 各情報の開始位置をoffsetとしている。
            // - bench_threshold_offset   = 0
            // - bench_left_offset        = node_count
            // - bench_right_offset       = 2 * node_count
            // - bench_feature_val_offset = 3 * node_count
            // - bench_label_offset       = 4 * node_count
            auto AddConstIdx = [&](const RepShare64 &idx, uint64_t offset, RepShare64 &out) {
                RepShare64 off = MakePublicShare(offset);
                rss.EvaluateAdd(idx, off, out);
            };

            // 共有されたidxでDBにRingOAでアクセスして値を取り出す
            auto ObliviousRead = [&](const RepShare64 &idx, RepShare64 &out) {
                eval.Evaluate(chls, key, uv_prev, uv_next, db_view, idx, out);
            };

            // ic_paramsはDCFで必要なパラメータ一式を格納
            // dcf_in_bits:
            //     --bench_dbits <n> を指定すればその値
            //     指定しなければ kBenchDbBits
            // dcf_out_bits:
            //     --bench_ringbits <n> を指定すればその値
            //     指定しなければ kBenchRingBits
            const uint64_t dcf_in_bits  = ic_params.GetInputDomainBits();
            const uint64_t dcf_out_bits = ic_params.GetDdcfOutputBitsize();

            // 下位k bitsだけ取り出す。DCFの入出力でのみ使用される
            // Mod2Nメソッドとほぼ同じことやってる
            auto MaskValue = [](uint64_t value, uint64_t bits) -> uint64_t {
                if (bits >= 64)
                    return value;
                uint64_t mask = (bits == 64) ? std::numeric_limits<uint64_t>::max() : ((1ULL << bits) - 1ULL);
                return value & mask;
            };

            // RSSシェア→2者間加法シェアの変換
            // party2のシェアをparty0,1に配分
            auto ConvertReplicatedToAdditive = [&](const RepShare64 &sh, uint64_t &out) {
                if (party_id == 2) {
                    uint64_t r = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_in_bits);
                    uint64_t x2 = Mod2N(sh[0], dcf_in_bits);
                    uint64_t masked = Mod2N(x2 - r, dcf_in_bits);
                    chls.next.send(r);
                    chls.prev.send(masked);
                    out = 0;
                } else if (party_id == 0) {
                    uint64_t r = 0;
                    chls.prev.recv(r);
                    out = Mod2N(sh[0] + r, dcf_in_bits);
                } else {
                    uint64_t masked = 0;
                    chls.next.recv(masked);
                    out = Mod2N(sh[0] + masked, dcf_in_bits);
                }
            };

            // 2者間加法シェアからRSSへの変換
            // p0,1のシェアを元に、新しいシェアs0,s1,s2を作成。各partyが2つずつ持つ
            auto ConvertSsBitToReplicated = [&](uint64_t local_share, RepShare64 &bit_sh) {
                if (party_id == 0) {
                    uint64_t s0 = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_out_bits);
                    chls.next.send(s0);
                    uint64_t masked = Mod2N(local_share - s0, dcf_out_bits);
                    chls.prev.send(masked);
                    uint64_t s2 = 0;
                    chls.prev.recv(s2);
                    bit_sh[0] = Mod2N(s0, d);
                    bit_sh[1] = Mod2N(s2, d);
                } else if (party_id == 1) {
                    uint64_t s0 = 0;
                    chls.prev.recv(s0);
                    uint64_t s1 = MaskValue(ringoa::GlobalRng::Rand<uint64_t>(), dcf_out_bits);
                    chls.next.send(s1);
                    uint64_t masked = Mod2N(local_share - s1, dcf_out_bits);
                    chls.next.send(masked);
                    bit_sh[0] = Mod2N(s1, d);
                    bit_sh[1] = Mod2N(s0, d);
                } else {
                    uint64_t s1 = 0;
                    chls.prev.recv(s1);
                    uint64_t masked_from_p0 = 0;
                    chls.next.recv(masked_from_p0);
                    uint64_t masked_from_p1 = 0;
                    chls.prev.recv(masked_from_p1);
                    uint64_t s2 = Mod2N(masked_from_p0 + masked_from_p1, dcf_out_bits);
                    chls.next.send(s2);
                    bit_sh[0] = Mod2N(s2, d);
                    bit_sh[1] = Mod2N(s1, d);
                }
            };

            timer_mgr.SelectTimer(timer_eval);
            for (uint64_t iter = 0; iter < repeat; ++iter) {
                RepShare64 current_idx = index_sh;
                RepShare64 label_share;

                for (uint32_t depth = 0; depth < bench_tree_depth; ++depth) {
                    RepShare64 thr_idx, left_idx, right_idx, feature_val_idx;
                    RepShare64 thr_sh, left_sh, right_sh, feature_val;

                    AddConstIdx(current_idx, bench_threshold_offset, thr_idx);
                    
                    timer_mgr.Start();
                    ObliviousRead(thr_idx, thr_sh);
                    timer_mgr.Stop();

                    AddConstIdx(current_idx, bench_left_offset, left_idx);
                    
                    timer_mgr.Start();
                    ObliviousRead(left_idx, left_sh);
                    timer_mgr.Stop();

                    AddConstIdx(current_idx, bench_right_offset, right_idx);
                    
                    timer_mgr.Start();
                    ObliviousRead(right_idx, right_sh);
                    timer_mgr.Stop();

                    AddConstIdx(current_idx, bench_feature_val_offset, feature_val_idx);
                    
                    timer_mgr.Start();
                    ObliviousRead(feature_val_idx, feature_val);

                    // DCFで使用。(特徴量の値-ノードの閾値)を計算
                    // DCFでは delta<0 かどうかを判定。その後、1 - cmp_bitに反転するから、最終的にはfeature_val < thr の判定ビット
                    RepShare64 delta_sh;
                    rss.EvaluateSub(feature_val, thr_sh, delta_sh);

                    RepShare64 cmp_bit;
                    uint64_t delta_part  = 0;
                    ConvertReplicatedToAdditive(delta_sh, delta_part);

                    // party0,1,2が並列で実行される。
                    // DCFはparty0,1のみで実行、party2は参加しない
                    // ConvertSsBitToReplicated の中での通信で同期が行われる
                    if (party_id < 2) {
                        osuCrypto::Channel &dcf_chl = (party_id == 0) ? chls.next : chls.prev;
                        uint64_t              bit_share = dcf_eval->EvaluateSharedInput(dcf_chl, *dcf_key, delta_part, 0);
                        ConvertSsBitToReplicated(bit_share, cmp_bit);
                    } else {
                        ConvertSsBitToReplicated(0, cmp_bit);
                    }
                    timer_mgr.Stop();

                    // DCFでの比較結果と、今回使いたいcmp_bitの向きが違うので、1-cmp_bit でビット反転する
                    RepShare64 one_sh = MakePublicShare(1);
                    RepShare64 cmp_lt;
                    rss.EvaluateSub(one_sh, cmp_bit, cmp_lt);
                    cmp_bit = cmp_lt;

                    timer_mgr.Start();
                    RepShare64 next_idx;
                    // z = x + comp·(y − x)の計算
                    // comp = 0ならx, 1ならy
                    rss.EvaluateSelect(chls, right_sh, left_sh, cmp_bit, next_idx);
                    current_idx = next_idx;
                }

                timer_mgr.Stop();
                RepShare64 label_idx;
                AddConstIdx(current_idx, bench_label_offset, label_idx);

                timer_mgr.Start();
                ObliviousRead(label_idx, label_share);

                uint64_t local_res = 0;
                rss.Open(chls, label_share, local_res);
                result = local_res;
                timer_mgr.Stop("d=" + ToString(d) + " iter=" + ToString(iter));
            }

            timer_mgr.PrintCurrentResults("d=" + ToString(d), ringoa::TimeUnit::MILLISECONDS, true);
        };
    };

    auto task_p0 = MakeTask(0);
    auto task_p1 = MakeTask(1);
    auto task_p2 = MakeTask(2);

    ThreePartyNetworkManager net_mgr;
    net_mgr.AutoConfigure(party_id, task_p0, task_p1, task_p2);
    net_mgr.WaitForCompletion();

    Logger::InfoLog(LOC, "Result: " + ToString(result));
    if (result != expected_label)
        throw osuCrypto::UnitTestFail("Pdte_Online_Bench failed: result = " + ToString(result) +
                                      ", expected = " + ToString(expected_label));
    Logger::InfoLog(LOC, "Pdte_Online_Bench - Completed");
    Logger::ExportLogListAndClear(kLogRingOaPath + "pdte_online_p" + ToString(party_id) + "_" + network, true);
}

}    // namespace test_ringoa
