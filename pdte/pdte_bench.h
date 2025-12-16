#ifndef BENCH_PDTE_BENCH_H_
#define BENCH_PDTE_BENCH_H_

#include <cryptoTools/Common/CLP.h>

namespace test_ringoa {

void Pdte_Offline_Bench(const osuCrypto::CLP &cmd);
void Pdte_Online_Bench(const osuCrypto::CLP &cmd);

}    // namespace bench_ringoa

#endif    // BENCH_PDTE_BENCH_H_
