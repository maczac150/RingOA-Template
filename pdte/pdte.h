#ifndef EXAMPLE_PDTE_H_
#define EXAMPLE_PDTE_H_

#include <cryptoTools/Common/CLP.h>

namespace test_ringoa {

void Pdte_Offline_Test();
void Pdte_Online_Test(const osuCrypto::CLP &cmd);
void Pdte_Offline_Bench(const osuCrypto::CLP &cmd);
void Pdte_Online_Bench(const osuCrypto::CLP &cmd);

}    // namespace test_ringoa

#endif    // EXAMPLE_PDTE_H_
