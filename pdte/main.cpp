#include <RingOA/utils/logger.h>
#include <RingOA/utils/rng.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/TestCollection.h>
#include <random>
#include <tests_cryptoTools/UnitTests.h>

#include "pdte.h"

namespace test_ringoa {

void RegisterTests(osuCrypto::TestCollection &t) {

    // t.add("DpfPir_Naive_Offline_Test", DpfPir_Naive_Offline_Test);
    // t.add("DpfPir_Naive_Online_Test", DpfPir_Naive_Online_Test);
    // t.add("DpfPir_Offline_Test", DpfPir_Offline_Test);
    // t.add("DpfPir_Online_Test", DpfPir_Online_Test);
    t.add("Pdte_Offline_Test", Pdte_Offline_Test);
    t.add("Pdte_Online_Test", Pdte_Online_Test);
}

}    // namespace test_ringoa

namespace {

std::vector<std::string>
    helpTags{"h", "help"},
    listTags{"l", "list"},
    testTags{"t", "test"},
    unitTags{"u", "unitTests"},
    suiteTags{"s", "suite"},
    repeatTags{"repeat"},
    loopTags{"loop"};

void PrintHelp() {
    std::cout << "Usage: test_program [OPTIONS]\n";
    std::cout << "Options:\n";
    std::cout << "  -unit, -u           Run all unit tests.\n";
    std::cout << "  -list, -l           List all available tests.\n";
    std::cout << "  -test=<Index>, -t   Run the specified test by its index.\n";
    std::cout << "  -suite=<Name>, -s   Run the specified test suite.\n";
    std::cout << "  -repeat=<Count>     Specify the number of repetitions for the test (default: 1).\n";
    std::cout << "  -loop=<Count>       Repeat the entire test execution for the specified number of loops (default: 1).\n";
    std::cout << "  -help, -h           Display this help message.\n";
}

}    // namespace

int main(int argc, char **argv) {
    try {
#ifndef USE_FIXED_RANDOM_SEED
        {
            std::random_device rd;
            osuCrypto::block   seed = osuCrypto::toBlock(rd(), rd());
            ringoa::GlobalRng::Initialize(seed);
        }
#else
        ringoa::GlobalRng::Initialize();
#endif

        osuCrypto::CLP            cmd(argc, argv);
        osuCrypto::TestCollection tests;
        test_ringoa::RegisterTests(tests);

        // Display help message
        if (cmd.isSet(helpTags)) {
            PrintHelp();
            return 0;
        }

        // Display available tests
        if (cmd.isSet(listTags)) {
            tests.list();
            return 0;
        }

        // Handle test execution
        if (cmd.hasValue(testTags)) {
            auto testIdxs    = cmd.getMany<osuCrypto::u64>(testTags);
            int  repeatCount = cmd.getOr(repeatTags, 1);
            int  loopCount   = cmd.getOr(loopTags, 1);

            if (testIdxs.empty()) {
                std::cerr << "Error: No test index specified.\n";
                return 1;
            }

            // Execute tests in a loop
            for (int i = 0; i < loopCount; ++i) {
                auto result = tests.run(testIdxs, repeatCount, &cmd);
                if (result != osuCrypto::TestCollection::Result::passed) {
                    return 1;    // Exit on failure
                }
            }
            return 0;    // Success
        }

        if (cmd.hasValue(suiteTags)) {
            auto prefix = cmd.get<std::string>(suiteTags);

            // search expects a list<string>
            std::list<std::string> queries = {prefix};

            // this will return all test indices whose name contains prefix
            auto idxs = tests.search(queries);

            if (idxs.empty()) {
                std::cerr << "No tests match suite string: " << prefix << "\n";
                return 1;
            }

            int rep  = cmd.getOr(repeatTags, 1);
            int loop = cmd.getOr(loopTags, 1);

            for (int i = 0; i < loop; ++i) {
                auto r = tests.run(idxs, rep, &cmd);
                if (r != osuCrypto::TestCollection::Result::passed)
                    return 1;
            }
            return 0;
        }

        // Unit test execution
        if (cmd.isSet(unitTags)) {
            ringoa::Logger::SetPrintLog(false);
            auto result = tests.runIf(cmd);
            if (result != osuCrypto::TestCollection::Result::passed) {
                return 1;    // Exit on failure
            }
            return 0;    // Success
        }

        // Invalid options
        std::cerr << "Error: No valid options specified.\n";
        PrintHelp();
        return 1;

    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
