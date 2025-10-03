# 二者間秘密計算におけるDPFベースのPIR

このREADMEは、2者間秘密計算で**DPFベースのPIR**を実装する際の、最低限必要な要素をまとめたガイドです。

---

## オフラインフェーズ

### 1. シェアの作り方

秘密のインデックス `idx` を加法秘密分散により2つのシェア `(idx0, idx1)` に分割します。

```cpp
AdditiveSharing2P ss(d);
uint64_t idx = 5;
std::pair<uint64_t, uint64_t> [idx0, idx1] = ss.Share(idx);
// auto [idx0, idx1] = ss.Share(idx);
// idx = idx0 + idx1 (mod 2^d)
```

### 2. 鍵の作り方

パラメータに基づいてDPFキー `(k0, k1)` を生成します。

```cpp
DpfPirParameters params(d);
DpfPirKeyGenerator gen(params, ss);
std::pair<DpfPirKey, DpfPirKey> [k0, k1] = gen.GenerateKeys();
// auto [k0, k1] = gen.GenerateKeys();
```

### 3. シェアのエクスポート方法

生成したインデックスシェアや鍵をファイルに保存します。

```cpp
KeyIo key_io; FileIo file_io;
key_io.SaveKey("key_0", k0);
key_io.SaveKey("key_1", k1);
file_io.WriteBinary("idx_0", idx0);
file_io.WriteBinary("idx_1", idx1);
```

### 4. オフラインフェーズのセットアップ

beaver tripleの生成をします。

```cpp
gen.OfflineSetUp(/*num_access=*/1, base);
```

---

## オンラインフェーズ

### 1. ネットワークの設定

2者間の通信を管理するネットワークマネージャを初期化します。

```cpp
TwoPartyNetworkManager net_mgr("DpfPir_Online_Test");
```

### 2. 各パーティのプロトコル実装方法

それぞれのパーティは、自分の役割に応じてラムダ関数内に処理を実装します。

```cpp
net_mgr.AutoConfigure(-1, server_task, client_task);
net_mgr.WaitForCompletion();
```

### 3. シェア・鍵の読み取り方

各パーティは、自分に対応する鍵とインデックスシェアを読み込みます。

```cpp
DpfPirKey key_0(0, params);
key_io.LoadKey("key_0", key_0);
file_io.ReadBinary("idx_0", idx0);

```

### 4. プロトコルの実行方法

各パーティは `Evaluate` を呼び出して結果のシェアを計算し、最後に再構成します。

```cpp
DpfPirEvaluator eval(params, ss);
std::vector<block> uv(1U << nu);
eval.OnlineSetUp(party_id, path);
uint64_t y_p = eval.Evaluate(chl, key, uv, DB, idx_share);

uint64_t y, y0, y1;
ss.Reconst(party_id, chl, y0, y1, y);
```
