#include "oa.h"

#include <cryptoTools/Common/TestCollection.h>

#include <RingOA/protocol/key_io.h>
#include <RingOA/protocol/ringoa.h>
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
using ringoa::proto::KeyIo;
using ringoa::proto::RingOaEvaluator;
using ringoa::proto::RingOaKey;
using ringoa::proto::RingOaKeyGenerator;
using ringoa::proto::RingOaParameters;
using ringoa::sharing::AdditiveSharing2P;
using ringoa::sharing::ReplicatedSharing3P;
using ringoa::sharing::RepShare64, ringoa::sharing::RepShareVec64, ringoa::sharing::RepShareView64;
using ringoa::sharing::ShareIo;

void RingOa_Offline_Test() {
    Logger::DebugLog(LOC, "RingOa_Offline_Test...");
    std::vector<RingOaParameters> params_list = {
        RingOaParameters(10),
        // RingOaParameters(15),
        // RingOaParameters(20),
    };

    for (const auto &params : params_list) {
        params.PrintParameters();
        uint64_t            d = params.GetParameters().GetInputBitsize();
        AdditiveSharing2P   ass(d);
        ReplicatedSharing3P rss(d);
        RingOaKeyGenerator  gen(params, ass);
        FileIo              file_io;
        ShareIo             sh_io;
        KeyIo               key_io;

        // Generate keys
        std::array<RingOaKey, 3> keys = gen.GenerateKeys();

        // Save keys
        std::string key_path = kTestOSPath + "ringoakey_d" + ToString(d);
        key_io.SaveKey(key_path + "_0", keys[0]);
        key_io.SaveKey(key_path + "_1", keys[1]);
        key_io.SaveKey(key_path + "_2", keys[2]);

        // Generate the database and index
        std::vector<uint64_t> database(1U << d);
        for (size_t i = 0; i < database.size(); ++i) {
            database[i] = i;
        }
        Logger::DebugLog(LOC, "Database: " + ToString(database));

        std::array<RepShareVec64, 3> database_sh = rss.ShareLocal(database);
        for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
            Logger::DebugLog(LOC, "Party " + ToString(p) + " db: " + database_sh[p].ToString());
        }

        // Save data
        std::string db_path = kTestOSPath + "ringoadb_d" + ToString(d);

        file_io.WriteBinary(db_path, database);
        for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
            sh_io.SaveShare(db_path + "_" + ToString(p), database_sh[p]);
        }

        // Generate a random index
        uint64_t index = ass.GenerateRandomValue();
        Logger::DebugLog(LOC, "Index: " + ToString(index));
        std::array<RepShare64, 3> index_sh = rss.ShareLocal(index);
        for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
            Logger::DebugLog(LOC, "Party " + ToString(p) + " index share: " + index_sh[p].ToString());
        }
        std::string idx_path = kTestOSPath + "ringoaidx_d" + ToString(d);
        file_io.WriteBinary(idx_path, index);
        for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
            sh_io.SaveShare(idx_path + "_" + ToString(p), index_sh[p]);
        }

        // Offline setup
        gen.OfflineSetUp(3, kTestOSPath);
        rss.OfflineSetUp(kTestOSPath + "prf");
    }
    Logger::DebugLog(LOC, "RingOa_Offline_Test - Passed");
}

void RingOa_Online_Test(const osuCrypto::CLP &cmd) {
    Logger::DebugLog(LOC, "RingOa_Additive_Online_Test...");
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
            throw osuCrypto::UnitTestFail("RingOa_Online_Test failed: result = " + ToString(result) +
                                          ", expected = " + ToString(database[index]));
    }
    Logger::DebugLog(LOC, "RingOa_Online_Test - Passed");
}

}    // namespace test_ringoa
