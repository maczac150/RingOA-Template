#ifndef EXAMPLE_OA_TEST_H_
#define EXAMPLE_OA_TEST_H_

#include <cryptoTools/Common/CLP.h>

namespace test_ringoa {

void RingOa_Offline_Test();
void RingOa_Online_Test(const osuCrypto::CLP &cmd);

}    // namespace test_ringoa

#endif    // EXAMPLE_OA_TEST_H_
