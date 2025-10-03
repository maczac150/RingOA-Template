#include "dpf_pir.h"

#include <cryptoTools/Common/TestCollection.h>

#include <RingOA/protocol/dpf_pir.h>
#include <RingOA/protocol/key_io.h>
#include <RingOA/sharing/additive_2p.h>
#include <RingOA/utils/file_io.h>
#include <RingOA/utils/logger.h>
#include <RingOA/utils/network.h>
#include <RingOA/utils/rng.h>
#include <RingOA/utils/timer.h>
#include <RingOA/utils/to_string.h>
#include <RingOA/utils/utils.h>

namespace {

const std::string kCurrentPath = ringoa::GetCurrentDirectory();
const std::string kTestEqPath  = kCurrentPath + "/data/test/";

}    // namespace

namespace test_ringoa {

using ringoa::block;
using ringoa::FileIo;
using ringoa::FormatType;
using ringoa::GlobalRng;
using ringoa::Logger;
using ringoa::Mod2N;
using ringoa::ToString, ringoa::Format;
using ringoa::TwoPartyNetworkManager;
using ringoa::proto::DpfPirEvaluator;
using ringoa::proto::DpfPirKey;
using ringoa::proto::DpfPirKeyGenerator;
using ringoa::proto::DpfPirParameters;
using ringoa::proto::KeyIo;
using ringoa::sharing::AdditiveSharing2P;

void DpfPir_Naive_Offline_Test() {
    Logger::DebugLog(LOC, "DpfPir_Naive_Offline_Test...");
    std::vector<DpfPirParameters> params_list = {
        DpfPirParameters(5, 5),
    };

    for (const DpfPirParameters &params : params_list) {
        params.PrintParameters();
        uint64_t           d = params.GetDatabaseSize();
        AdditiveSharing2P  ss(d);
        DpfPirKeyGenerator gen(params, ss);
        KeyIo              key_io;
        FileIo             file_io;

        // Generate keys
        std::pair<DpfPirKey, DpfPirKey> keys = gen.GenerateKeys();

        // Save keys
        std::string key_path = kTestEqPath + "dpfpirkey_naive_d" + ToString(d);
        key_io.SaveKey(key_path + "_0", keys.first);
        key_io.SaveKey(key_path + "_1", keys.second);

        // Generate input
        uint64_t                      idx    = 5;
        std::pair<uint64_t, uint64_t> idx_sh = ss.Share(idx);
        Logger::DebugLog(LOC, "idx: " + ToString(idx));
        Logger::DebugLog(LOC, "idx_sh: " + ToString(idx_sh.first) + ", " + ToString(idx_sh.second));

        // Generate the database and index
        std::vector<uint64_t> database(1U << d);
        for (size_t i = 0; i < database.size(); ++i) {
            database[i] = i;
        }
        Logger::DebugLog(LOC, "Database: " + ToString(database));

        // Save input
        std::string idx_path = kTestEqPath + "idx_d" + ToString(d);
        file_io.WriteBinary(idx_path + "_0", idx_sh.first);
        file_io.WriteBinary(idx_path + "_1", idx_sh.second);

        // Save database
        std::string db_path = kTestEqPath + "db_d" + ToString(d);
        file_io.WriteBinary(db_path, database);

        // Offline setup
        gen.OfflineSetUp(1, kTestEqPath);
    }
    Logger::DebugLog(LOC, "DpfPir_Naive_Offline_Test - Passed");
}

void DpfPir_Naive_Online_Test() {
    Logger::DebugLog(LOC, "DpfPir_Naive_Online_Test...");
    std::vector<DpfPirParameters> params_list = {
        DpfPirParameters(5, 5),
    };

    for (const DpfPirParameters &params : params_list) {
        // params.PrintDpfPirParameters();
        uint64_t d = params.GetDatabaseSize();
        KeyIo    key_io;
        FileIo   file_io;

        // Start network communication
        TwoPartyNetworkManager net_mgr("DpfPir_Naive_Online_Test");

        std::string key_path = kTestEqPath + "dpfpirkey_naive_d" + ToString(d);
        std::string idx_path = kTestEqPath + "idx_d" + ToString(d);
        std::string db_path  = kTestEqPath + "db_d" + ToString(d);

        uint64_t              idx_0, idx_1;
        uint64_t              y, y_0, y_1;
        std::vector<uint64_t> database;
        file_io.ReadBinary(db_path, database);

        // Server task
        auto server_task = [&](oc::Channel &chl) {
            AdditiveSharing2P ss(d);
            DpfPirEvaluator   eval(params, ss);
            // Load keys
            DpfPirKey key_0(0, params);
            key_io.LoadKey(key_path + "_0", key_0);

            // Load input
            file_io.ReadBinary(idx_path + "_0", idx_0);

            std::vector<uint64_t> uv(1U << d);

            // Online Setup
            eval.OnlineSetUp(0, kTestEqPath);

            // Evaluate
            y_0 = eval.EvaluateNaive(chl, key_0, uv, database, idx_0);

            // Send output
            ss.Reconst(0, chl, y_0, y_1, y);
            Logger::DebugLog(LOC, "[P0] y: " + ToString(y));
        };

        // Client task
        auto client_task = [&](oc::Channel &chl) {
            AdditiveSharing2P ss(d);
            DpfPirEvaluator   eval(params, ss);
            // Load keys
            DpfPirKey key_1(1, params);
            key_io.LoadKey(key_path + "_1", key_1);

            // Load input
            file_io.ReadBinary(idx_path + "_1", idx_1);

            std::vector<uint64_t> uv(1U << d);

            // Online Setup
            eval.OnlineSetUp(1, kTestEqPath);

            // Evaluate
            y_1 = eval.EvaluateNaive(chl, key_1, uv, database, idx_1);

            // Send output
            ss.Reconst(1, chl, y_0, y_1, y);
            Logger::DebugLog(LOC, "[P1] y: " + ToString(y));
        };

        net_mgr.AutoConfigure(-1, server_task, client_task);
        net_mgr.WaitForCompletion();

        if (y != 5)
            throw oc::UnitTestFail("y is not equal to 5");
    }
    Logger::DebugLog(LOC, "DpfPir_Naive_Online_Test - Passed");
}

void DpfPir_Offline_Test() {
    Logger::DebugLog(LOC, "DpfPir_Offline_Test...");
    std::vector<DpfPirParameters> params_list = {
        DpfPirParameters(10),
    };

    for (const DpfPirParameters &params : params_list) {
        params.PrintParameters();
        uint64_t           d = params.GetDatabaseSize();
        AdditiveSharing2P  ss(d);
        DpfPirKeyGenerator gen(params, ss);
        KeyIo              key_io;
        FileIo             file_io;

        // Generate keys
        std::pair<DpfPirKey, DpfPirKey> keys = gen.GenerateKeys();

        // Save keys
        std::string key_path = kTestEqPath + "dpfpirkey_d" + ToString(d);
        key_io.SaveKey(key_path + "_0", keys.first);
        key_io.SaveKey(key_path + "_1", keys.second);

        // Generate input
        uint64_t                      idx    = 5;
        std::pair<uint64_t, uint64_t> idx_sh = ss.Share(idx);
        Logger::DebugLog(LOC, "idx: " + ToString(idx));
        Logger::DebugLog(LOC, "idx_sh: " + ToString(idx_sh.first) + ", " + ToString(idx_sh.second));

        // Generate the database and index
        std::vector<uint64_t> database(1U << d);
        for (size_t i = 0; i < database.size(); ++i) {
            database[i] = i;
        }
        Logger::DebugLog(LOC, "Database: " + ToString(database));

        // Save input
        std::string idx_path = kTestEqPath + "idx_d" + ToString(d);
        file_io.WriteBinary(idx_path + "_0", idx_sh.first);
        file_io.WriteBinary(idx_path + "_1", idx_sh.second);

        // Save database
        std::string db_path = kTestEqPath + "db_d" + ToString(d);
        file_io.WriteBinary(db_path, database);

        // Offline setup
        gen.OfflineSetUp(1, kTestEqPath);
    }
    Logger::DebugLog(LOC, "DpfPir_Offline_Test - Passed");
}

void DpfPir_Online_Test() {
    Logger::DebugLog(LOC, "DpfPir_Online_Test...");
    std::vector<DpfPirParameters> params_list = {
        DpfPirParameters(10),
    };

    for (const DpfPirParameters &params : params_list) {
        // params.PrintDpfPirParameters();
        uint64_t d  = params.GetDatabaseSize();
        uint64_t nu = params.GetParameters().GetTerminateBitsize();
        KeyIo    key_io;
        FileIo   file_io;

        // Start network communication
        TwoPartyNetworkManager net_mgr("DpfPir_Online_Test");

        std::string key_path = kTestEqPath + "dpfpirkey_d" + ToString(d);
        std::string idx_path = kTestEqPath + "idx_d" + ToString(d);
        std::string db_path  = kTestEqPath + "db_d" + ToString(d);

        uint64_t              idx_0, idx_1;
        uint64_t              y, y_0, y_1;
        std::vector<uint64_t> database;
        file_io.ReadBinary(db_path, database);

        // Server task
        auto server_task = [&](oc::Channel &chl) {
            AdditiveSharing2P ss(d);
            DpfPirEvaluator   eval(params, ss);
            // Load keys
            DpfPirKey key_0(0, params);
            key_io.LoadKey(key_path + "_0", key_0);

            // Load input
            file_io.ReadBinary(idx_path + "_0", idx_0);

            std::vector<block> uv(1U << nu);

            // Online Setup
            eval.OnlineSetUp(0, kTestEqPath);

            // Evaluate
            y_0 = eval.Evaluate(chl, key_0, uv, database, idx_0);

            // Send output
            ss.Reconst(0, chl, y_0, y_1, y);
            Logger::DebugLog(LOC, "[P0] y: " + ToString(y));
        };

        // Client task
        auto client_task = [&](oc::Channel &chl) {
            AdditiveSharing2P ss(d);
            DpfPirEvaluator   eval(params, ss);
            // Load keys
            DpfPirKey key_1(1, params);
            key_io.LoadKey(key_path + "_1", key_1);

            // Load input
            file_io.ReadBinary(idx_path + "_1", idx_1);

            std::vector<block> uv(1U << nu);

            // Online Setup
            eval.OnlineSetUp(1, kTestEqPath);

            // Evaluate
            y_1 = eval.Evaluate(chl, key_1, uv, database, idx_1);

            // Send output
            ss.Reconst(1, chl, y_0, y_1, y);
            Logger::DebugLog(LOC, "[P1] y: " + ToString(y));
        };

        net_mgr.AutoConfigure(-1, server_task, client_task);
        net_mgr.WaitForCompletion();

        if (y != 5)
            throw oc::UnitTestFail("y is not equal to 5");
    }
    Logger::DebugLog(LOC, "DpfPir_Online_Test - Passed");
}

}    // namespace test_ringoa
