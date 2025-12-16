#include "pdte_bench.h"

#include <cryptoTools/Common/TestCollection.h>

#include "RingOA/protocol/key_io.h"
#include "RingOA/protocol/ringoa.h"
#include "RingOA/protocol/ringoa_fsc.h"
#include "RingOA/sharing/additive_2p.h"
#include "RingOA/sharing/additive_3p.h"
#include "RingOA/sharing/share_io.h"
#include "RingOA/utils/logger.h"
#include "RingOA/utils/network.h"
#include "RingOA/utils/timer.h"
#include "RingOA/utils/utils.h"
#include "bench_common.h"

namespace bench_ringoa {

using ringoa::block;
using ringoa::Channels;
using ringoa::FileIo;
using ringoa::Logger;
using ringoa::Mod2N;
using ringoa::ThreePartyNetworkManager;
using ringoa::TimerManager;
using ringoa::ToString, ringoa::Format;
using ringoa::proto::KeyIo;
using ringoa::proto::RingOaEvaluator;
using ringoa::proto::RingOaFscEvaluator;
using ringoa::proto::RingOaFscKey;
using ringoa::proto::RingOaFscKeyGenerator;
using ringoa::proto::RingOaFscParameters;
using ringoa::proto::RingOaKey;
using ringoa::proto::RingOaKeyGenerator;
using ringoa::proto::RingOaParameters;
using ringoa::sharing::AdditiveSharing2P;
using ringoa::sharing::ReplicatedSharing3P;
using ringoa::sharing::RepShare64;
using ringoa::sharing::RepShareVec64;
using ringoa::sharing::RepShareView64;
using ringoa::sharing::ShareIo;

void RingOa_Offline_Bench(const osuCrypto::CLP &cmd) {
    uint64_t              repeat      = cmd.getOr("repeat", kRepeatDefault);
    std::vector<uint64_t> db_bitsizes = SelectBitsizes(cmd);

    Logger::InfoLog(LOC, "RingOA Offline Benchmark started (repeat=" + ToString(repeat) + ")");

    for (auto db_bitsize : db_bitsizes) {
        RingOaParameters params(db_bitsize);
        params.PrintParameters();

        uint64_t            d = params.GetParameters().GetInputBitsize();
        AdditiveSharing2P   ass(d);
        ReplicatedSharing3P rss(d);
        RingOaKeyGenerator  gen(params, ass);
        FileIo              file_io;
        ShareIo             sh_io;
        KeyIo               key_io;
        TimerManager        timer_mgr;

        std::string key_path = kBenchRingOAPath + "ringoakey_d" + ToString(d);
        std::string db_path  = kBenchRingOAPath + "db_d" + ToString(d);
        std::string idx_path = kBenchRingOAPath + "idx_d" + ToString(d);

        // 1) KeyGen
        {
            const std::string timer_name = "RingOA KeyGen";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            for (uint64_t i = 0; i < repeat; ++i) {
                timer_mgr.Start();
                std::array<RingOaKey, 3> keys = gen.GenerateKeys();
                timer_mgr.Stop("d=" + ToString(d) + " iter=" + ToString(i));

                // Persist keys for each party
                key_io.SaveKey(key_path + "_0", keys[0]);
                key_io.SaveKey(key_path + "_1", keys[1]);
                key_io.SaveKey(key_path + "_2", keys[2]);
            }
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MICROSECONDS,
                /*show_details=*/true);
        }

        // 2) OfflineSetUp timing (measured once per d)
        {
            const std::string timer_name = "RingOA OfflineSetUp";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            timer_mgr.Start();
            gen.OfflineSetUp(repeat, kBenchRingOAPath);
            rss.OfflineSetUp(kBenchRingOAPath + "prf");
            timer_mgr.Stop("d=" + ToString(d) + " iter=0");
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MICROSECONDS,
                /*show_details=*/true);
        }

        // 3) Data generation + secret sharing timing (measured once per d)
        {
            const std::string timer_name = "RingOA DataGen";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            timer_mgr.Start();
            // Build database of size 2^d with values 0..(2^d-1)
            std::vector<uint64_t> database(1ULL << d);
            for (size_t i = 0; i < database.size(); ++i) {
                database[i] = static_cast<uint64_t>(i);
            }

            // Random query index over Z_{2^d}
            uint64_t index = ass.GenerateRandomValue();
            timer_mgr.Mark("DataGen d=" + ToString(d));

            // 3-party replicated shares (local)
            std::array<RepShareVec64, 3> database_sh = rss.ShareLocal(database);
            std::array<RepShare64, 3>    index_sh    = rss.ShareLocal(index);
            timer_mgr.Mark("ShareGen d=" + ToString(d));

            // Save per-party shares
            for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
                sh_io.SaveShare(db_path + "_" + ToString(p), database_sh[p]);
                sh_io.SaveShare(idx_path + "_" + ToString(p), index_sh[p]);
            }
            timer_mgr.Mark("ShareSave d=" + ToString(d));
            timer_mgr.Stop("d=" + ToString(d) + " iter=0");
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MILLISECONDS,
                /*show_details=*/true);
        }
    }

    Logger::InfoLog(LOC, "RingOA Offline Benchmark completed");
    Logger::ExportLogListAndClear(kLogRingOaPath + "ringoa_offline_bench", /*use_timestamp=*/true);
}

void RingOa_Online_Bench(const osuCrypto::CLP &cmd) {
    uint64_t              repeat      = cmd.getOr("repeat", kRepeatDefault);
    int                   party_id    = cmd.isSet("party") ? cmd.get<int>("party") : -1;
    std::string           network     = cmd.isSet("network") ? cmd.get<std::string>("network") : "";
    std::vector<uint64_t> db_bitsizes = SelectBitsizes(cmd);

    Logger::InfoLog(LOC, "RingOA Online Benchmark started (repeat=" + ToString(repeat) +
                             ", party=" + ToString(party_id) + ")");

    auto MakeTask = [&](int p) {
        const std::string ptag = "(P" + ToString(p) + ")";

        return [=](osuCrypto::Channel &chl_next, osuCrypto::Channel &chl_prev) {
            for (auto db_bitsize : db_bitsizes) {
                RingOaParameters params(db_bitsize);
                params.PrintParameters();

                uint64_t d  = params.GetParameters().GetInputBitsize();
                uint64_t nu = params.GetParameters().GetTerminateBitsize();

                std::string key_path = kBenchRingOAPath + "ringoakey_d" + ToString(d);
                std::string db_path  = kBenchRingOAPath + "db_d" + ToString(d);
                std::string idx_path = kBenchRingOAPath + "idx_d" + ToString(d);

                // Timers
                TimerManager      timer_mgr;
                const std::string timer_setup_name = "RingOA OnlineSetUp " + ptag;
                const std::string timer_eval_name  = "RingOA Eval " + ptag;
                int32_t           timer_setup      = timer_mgr.CreateNewTimer(timer_setup_name);
                int32_t           timer_eval       = timer_mgr.CreateNewTimer(timer_eval_name);

                // --- OnlineSetUp timing ---
                timer_mgr.SelectTimer(timer_setup);
                timer_mgr.Start();

                ReplicatedSharing3P rss(d);
                AdditiveSharing2P   ass_prev(d), ass_next(d);
                RingOaEvaluator     eval(params, rss, ass_prev, ass_next);
                Channels            chls(p, chl_prev, chl_next);
                RepShare64          result_sh;

                // Load key for this party
                RingOaKey key(p, params);
                KeyIo     key_io;
                key_io.LoadKey(key_path + "_" + ToString(p), key);

                // Load shares (database and index)
                RepShareVec64 database_sh;
                RepShare64    index_sh;
                ShareIo       sh_io;
                sh_io.LoadShare(db_path + "_" + ToString(p), database_sh);
                sh_io.LoadShare(idx_path + "_" + ToString(p), index_sh);

                // Buffers sized by terminate bitsize
                std::vector<ringoa::block> uv_prev(1ULL << nu), uv_next(1ULL << nu);

                // Online setup for evaluator/PRF
                eval.OnlineSetUp(p, kBenchRingOAPath);
                rss.OnlineSetUp(p, kBenchRingOAPath + "prf");

                timer_mgr.Stop("d=" + ToString(d) + " iter=0");

                timer_mgr.PrintCurrentResults(
                    "d=" + ToString(d),
                    ringoa::TimeUnit::MICROSECONDS,
                    /*show_details=*/true);

                // --- Eval timing ---
                timer_mgr.SelectTimer(timer_eval);

                for (uint64_t i = 0; i < repeat; ++i) {
                    timer_mgr.Start();
                    eval.Evaluate(chls, key,
                                  uv_prev, uv_next,
                                  RepShareView64(database_sh), index_sh, result_sh);
                    timer_mgr.Stop("d=" + ToString(d) + " iter=" + ToString(i));

                    if (i < 2) {
                        Logger::InfoLog(LOC, "d=" + ToString(d) +
                                                 " total_data_sent=" + ToString(chls.GetStats()) + " bytes");
                    }
                    chls.ResetStats();
                }

                timer_mgr.SelectTimer(timer_eval);
                timer_mgr.PrintCurrentResults(
                    "d=" + ToString(d),
                    ringoa::TimeUnit::MICROSECONDS,
                    /*show_details=*/true);
            }
        };
    };

    // Create tasks for parties 0, 1, and 2
    auto task0 = MakeTask(0);
    auto task1 = MakeTask(1);
    auto task2 = MakeTask(2);

    // Configure network and run
    ThreePartyNetworkManager net_mgr;
    net_mgr.AutoConfigure(party_id, task0, task1, task2);
    net_mgr.WaitForCompletion();

    Logger::InfoLog(LOC, "RingOA Online Benchmark completed");
    Logger::ExportLogListAndClear(kLogRingOaPath + "ringoa_online_p" + ToString(party_id) + "_" + network, /*use_timestamp=*/true);
}

void RingOa_Fsc_Offline_Bench(const osuCrypto::CLP &cmd) {
    uint64_t              repeat      = cmd.getOr("repeat", kRepeatDefault);
    std::vector<uint64_t> db_bitsizes = SelectBitsizes(cmd);

    Logger::InfoLog(LOC, "RingOA (FSC) Offline Benchmark started (repeat=" + ToString(repeat) + ")");

    for (auto db_bitsize : db_bitsizes) {
        RingOaFscParameters params(db_bitsize);
        params.PrintParameters();

        uint64_t              d = params.GetParameters().GetInputBitsize();
        AdditiveSharing2P     ass(d);
        ReplicatedSharing3P   rss(d);
        RingOaFscKeyGenerator gen(params, rss, ass);
        FileIo                file_io;
        ShareIo               sh_io;
        KeyIo                 key_io;
        TimerManager          timer_mgr;

        std::string key_path = kBenchRingOAPath + "ringoafsckey_d" + ToString(d);
        std::string db_path  = kBenchRingOAPath + "dbfsc_d" + ToString(d);
        std::string idx_path = kBenchRingOAPath + "idxfsc_d" + ToString(d);

        std::array<bool, 3> v_sign{};    // will be filled in DataGen

        // 1. Data generation + secret sharing timing
        {
            const std::string timer_name = "RingOaFsc DataGen";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            timer_mgr.Start();
            // Build database of size 2^d with values 0..(2^d-1)
            std::vector<uint64_t> database(1ULL << d);
            for (size_t i = 0; i < database.size(); ++i) {
                database[i] = static_cast<uint64_t>(i);
            }

            // Random query index over Z_{2^d}
            uint64_t index = ass.GenerateRandomValue();
            timer_mgr.Mark("DataGen d=" + ToString(d));

            // 3-party replicated shares (local) + FSC-specific sign bits
            std::array<RepShareVec64, 3> database_sh;
            gen.GenerateDatabaseShare(database, database_sh, v_sign);
            std::array<RepShare64, 3> index_sh = rss.ShareLocal(index);
            timer_mgr.Mark("ShareGen d=" + ToString(d));

            // Save per-party shares
            for (size_t p = 0; p < ringoa::sharing::kThreeParties; ++p) {
                sh_io.SaveShare(db_path + "_" + ToString(p), database_sh[p]);
                sh_io.SaveShare(idx_path + "_" + ToString(p), index_sh[p]);
            }
            timer_mgr.Mark("ShareSave d=" + ToString(d));
            timer_mgr.Stop("d=" + ToString(d) + " iter=0");
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MILLISECONDS,
                /*show_details=*/true);
        }

        // 2. KeyGen
        {
            const std::string timer_name = "RingOaFsc KeyGen";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            for (uint64_t i = 0; i < repeat; ++i) {
                timer_mgr.Start();
                std::array<RingOaFscKey, 3> keys = gen.GenerateKeys(v_sign);
                timer_mgr.Stop("d=" + ToString(d) + " iter=" + ToString(i));

                // Persist keys for each party
                key_io.SaveKey(key_path + "_0", keys[0]);
                key_io.SaveKey(key_path + "_1", keys[1]);
                key_io.SaveKey(key_path + "_2", keys[2]);
            }
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MICROSECONDS,
                /*show_details=*/true);
        }

        // 3. OfflineSetUp timing
        {
            const std::string timer_name = "RingOaFsc OfflineSetUp";
            int32_t           timer_id   = timer_mgr.CreateNewTimer(timer_name);
            timer_mgr.SelectTimer(timer_id);

            // Measured once per d (not per-iter)
            timer_mgr.Start();
            rss.OfflineSetUp(kBenchRingOAPath + "prf");
            timer_mgr.Stop("d=" + ToString(d) + " iter=0");
            timer_mgr.PrintCurrentResults(
                "d=" + ToString(d),
                ringoa::TimeUnit::MICROSECONDS,
                /*show_details=*/true);
        }
    }

    Logger::InfoLog(LOC, "RingOa_Fsc_Offline_Bench - Finished");
    // Keep your explicit export if desired for post-run analysis.
    Logger::ExportLogListAndClear(kLogRingOaPath + "ringoa_fsc_offline_bench", /*use_timestamp=*/false);
}

void RingOa_Fsc_Online_Bench(const osuCrypto::CLP &cmd) {
    uint64_t              repeat      = cmd.getOr("repeat", kRepeatDefault);
    int                   party_id    = cmd.isSet("party") ? cmd.get<int>("party") : -1;
    std::string           network     = cmd.isSet("network") ? cmd.get<std::string>("network") : "";
    std::vector<uint64_t> db_bitsizes = SelectBitsizes(cmd);

    Logger::InfoLog(LOC, "RingOA (FSC) Online Benchmark started (repeat=" + ToString(repeat) +
                             ", party=" + ToString(party_id) + ")");

    auto MakeTask = [&](int p) {
        const std::string ptag = "(P" + ToString(p) + ")";
        return [=](osuCrypto::Channel &chl_next, osuCrypto::Channel &chl_prev) {
            for (auto db_bitsize : db_bitsizes) {
                RingOaFscParameters params(db_bitsize);
                params.PrintParameters();
                uint64_t    d        = params.GetParameters().GetInputBitsize();
                uint64_t    nu       = params.GetParameters().GetTerminateBitsize();
                std::string key_path = kBenchRingOAPath + "ringoafsckey_d" + ToString(d);
                std::string db_path  = kBenchRingOAPath + "dbfsc_d" + ToString(d);
                std::string idx_path = kBenchRingOAPath + "idxfsc_d" + ToString(d);

                TimerManager      timer_mgr;
                const std::string timer_setup_name = "RingOA (FSC) OnlineSetUp " + ptag;
                const std::string timer_eval_name  = "RingOA (FSC) Eval " + ptag;
                int32_t           timer_setup      = timer_mgr.CreateNewTimer(timer_setup_name);
                int32_t           timer_eval       = timer_mgr.CreateNewTimer(timer_eval_name);

                timer_mgr.SelectTimer(timer_setup);
                timer_mgr.Start();

                ReplicatedSharing3P rss(d);
                AdditiveSharing2P   ass_prev(d), ass_next(d);
                RingOaFscEvaluator  eval(params, rss, ass_prev, ass_next);
                Channels            chls(p, chl_prev, chl_next);
                RepShare64          result_sh;

                RingOaFscKey key(p, params);
                KeyIo        key_io;
                key_io.LoadKey(key_path + "_" + ToString(p), key);

                RepShareVec64 database_sh;
                RepShare64    index_sh;
                ShareIo       sh_io;
                sh_io.LoadShare(db_path + "_" + ToString(p), database_sh);
                sh_io.LoadShare(idx_path + "_" + ToString(p), index_sh);

                std::vector<ringoa::block> uv_prev(1ULL << nu), uv_next(1ULL << nu);

                rss.OnlineSetUp(p, kBenchRingOAPath + "prf");

                timer_mgr.Stop("d=" + ToString(d) + " iter=0");
                timer_mgr.PrintCurrentResults("d=" + ToString(d), ringoa::TimeUnit::MICROSECONDS, true);

                timer_mgr.SelectTimer(timer_eval);
                for (uint64_t i = 0; i < repeat; ++i) {
                    timer_mgr.Start();
                    eval.Evaluate(chls, key,
                                  uv_prev, uv_next,
                                  RepShareView64(database_sh), index_sh, result_sh);
                    timer_mgr.Stop("d=" + ToString(d) + " iter=" + ToString(i));
                    if (i < 2)
                        Logger::InfoLog(LOC, "d=" + ToString(d) + " total_data_sent=" + ToString(chls.GetStats()) + " bytes");
                    chls.ResetStats();
                }
                timer_mgr.SelectTimer(timer_eval);
                timer_mgr.PrintCurrentResults("d=" + ToString(d), ringoa::TimeUnit::MICROSECONDS, true);
            }
        };
    };

    auto task0 = MakeTask(0);
    auto task1 = MakeTask(1);
    auto task2 = MakeTask(2);

    ThreePartyNetworkManager net_mgr;
    net_mgr.AutoConfigure(party_id, task0, task1, task2);
    net_mgr.WaitForCompletion();

    Logger::InfoLog(LOC, "RingOA (FSC) Online Benchmark completed");
    Logger::ExportLogListAndClear(kLogRingOaPath + "ringoa_fsc_online_p" + ToString(party_id) + "_" + network, /*use_timestamp=*/false);
}

}    // namespace bench_ringoa
