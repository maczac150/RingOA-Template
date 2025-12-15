#include "pdte.h"

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

void Pdte_Offline_Test() {
    Logger::DebugLog(LOC, "Pdte_Offline_Test...");

    RingOaParameters            ringoa_params(10);
    IntegerComparisonParameters ic_params(10, 10);
    SharedOtParameters          shared_params(10);
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

    // TODO:Generate the decision tree data and sharing
    // TODO:Generate the feature data and sharing

    // Offline setup
    ringoa_gen.OfflineSetUp(3, kTestOSPath);
    rss.OfflineSetUp(kTestOSPath + "prf");
    Logger::DebugLog(LOC, "Pdte_Offline_Test - Passed");
}

void Pdte_Online_Test(const osuCrypto::CLP &cmd) {
    Logger::DebugLog(LOC, "Pdte_Additive_Online_Test...");
    std::vector<RingOaParameters> params_list = {
        RingOaParameters(10),
        // RingOaParameters(15),
        // RingOaParameters(20),
    };

    for (const auto &params : params_list) {
        params.PrintParameters();
        uint64_t d  = params.GetParameters().GetInputBitsize();
        uint64_t nu = params.GetParameters().GetTerminateBitsize();
        FileIo   file_io;
        ShareIo  sh_io;

        uint64_t              result{0};
        std::string           key_path = kTestOSPath + "ringoakey_d" + ToString(d);
        std::string           db_path  = kTestOSPath + "ringoadb_d" + ToString(d);
        std::string           idx_path = kTestOSPath + "ringoaidx_d" + ToString(d);
        std::vector<uint64_t> database;
        uint64_t              index;
        file_io.ReadBinary(db_path, database);
        file_io.ReadBinary(idx_path, index);

        // Define the task for each party
        auto MakeTask = [&](int party_id) {
            return [=, &result](osuCrypto::Channel &chl_next, osuCrypto::Channel &chl_prev) {
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

                std::vector<ringoa::block> uv_prev(1U << nu), uv_next(1U << nu);

                // Setup the PRF keys
                eval.OnlineSetUp(party_id, kTestOSPath);
                rss.OnlineSetUp(party_id, kTestOSPath + "prf");

                // TODO:feature vectorのOblivious Access
                // TODO:thresholdとのcomparison(Distributed Comparison Function)
                // TODO:次に進むidxを計算
                // TODO:次のノード情報のOblivious Access

                // Evaluate
                RepShare64 result_sh;
                eval.Evaluate(chls, key, uv_prev, uv_next, RepShareView64(database_sh), index_sh, result_sh);

                RepShareVec64 index_vec_sh(2), result_vec_sh(2);
                index_vec_sh.Set(0, index_sh);
                index_vec_sh.Set(1, index_sh);
                eval.Evaluate_Parallel(chls, key, key, uv_prev, uv_next, RepShareView64(database_sh), index_vec_sh, result_vec_sh);

                // Open the result
                uint64_t              local_res = 0;
                std::vector<uint64_t> local_res_vec(2);

                rss.Open(chls, result_sh, local_res);
                rss.Open(chls, result_vec_sh, local_res_vec);
                Logger::DebugLog(LOC, "result_vec_sh: " + ToString(local_res_vec));
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

        if (result != database[index])
            throw osuCrypto::UnitTestFail("Pdte_Online_Test failed: result = " + ToString(result) +
                                          ", expected = " + ToString(database[index]));
    }
    Logger::DebugLog(LOC, "Pdte_Online_Test - Passed");
}

}    // namespace test_ringoa
