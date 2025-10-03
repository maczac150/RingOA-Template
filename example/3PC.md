# 三者間秘密計算におけるOblivious Access

`ReplicatedSharing3P` と `RingOa*` 系クラスを用いた三者間（P0, P1, P2）プロトコルの最小手順です。

## オフラインフェーズ

### 1. シェアの作り方（DB / index の複製分散シェア）

```cpp
uint64_t d = params.GetParameters().GetInputBitsize();
ReplicatedSharing3P rss(d);

std::vector<uint64_t> database(1ULL << d);
std::iota(database.begin(), database.end(), 0);

// Replicated shares of the database
std::array<RepShareVec64,3> db_sh = rss.ShareLocal(database);

// Replicated share of a secret index
uint64_t index = /* any secret index */;
std::array<RepShare64,3> idx_sh = rss.ShareLocal(index);
```

### 2. 鍵の作り方（各パーティ用の鍵3本）

```cpp
AdditiveSharing2P ass(d); // used internally for keygen if needed
RingOaKeyGenerator gen(params, ass);
std::array<RingOaKey,3> keys = gen.GenerateKeys();
```

### 3. シェアのエクスポート方法（Key/Share の保存）

```cpp
KeyIo  key_io;   // save/load RingOaKey
ShareIo sh_io;   // save/load replicated shares

// Keys
key_io.SaveKey(base+"ringoakey_d"+ToString(d)+"_0", keys[0]);
key_io.SaveKey(base+"ringoakey_d"+ToString(d)+"_1", keys[1]);
key_io.SaveKey(base+"ringoakey_d"+ToString(d)+"_2", keys[2]);

// Database shares
sh_io.SaveShare(base+"ringoadb_d"+ToString(d)+"_0", db_sh[0]);
sh_io.SaveShare(base+"ringoadb_d"+ToString(d)+"_1", db_sh[1]);
sh_io.SaveShare(base+"ringoadb_d"+ToString(d)+"_2", db_sh[2]);

// Index shares
sh_io.SaveShare(base+"ringoaidx_d"+ToString(d)+"_0", idx_sh[0]);
sh_io.SaveShare(base+"ringoaidx_d"+ToString(d)+"_1", idx_sh[1]);
sh_io.SaveShare(base+"ringoaidx_d"+ToString(d)+"_2", idx_sh[2]);
```

### 4. オフラインフェーズのセットアップ

beaver tripleの生成及びPRFの鍵の生成をします。

```cpp
RingOaKeyGenerator(params, ass).OfflineSetUp(/*num_access=*/3, base);
rss.OfflineSetUp(base+"prf");
```

---

## オンラインフェーズ

### 1. ネットワークの設定（3者）

```cpp
ThreePartyNetworkManager net; // provides two channels per party: prev/next
```

### 2. 各パーティのプロトコルの実装方法（タスク化）

```cpp
auto MakeTask = [&](int party_id){
  return [=](oc::Channel& chl_next, oc::Channel& chl_prev){
    // English comments only inside C++ code
    ReplicatedSharing3P rss(d);
    AdditiveSharing2P ass_prev(d), ass_next(d);
    RingOaEvaluator eval(params, rss, ass_prev, ass_next);
    Channels chls(party_id, chl_prev, chl_next); // wrapper

    // Load key/share
    KeyIo key_io; ShareIo sh_io; RepShareVec64 db_sh; RepShare64 idx_sh;
    RingOaKey key(party_id, params);
    key_io.LoadKey(base+"ringoakey_d"+ToString(d)+"_"+ToString(party_id), key);
    sh_io.LoadShare(base+"ringoadb_d"+ToString(d)+"_"+ToString(party_id), db_sh);
    sh_io.LoadShare(base+"ringoaidx_d"+ToString(d)+"_"+ToString(party_id), idx_sh);

    // Setup per-party PRFs and tables
    uint64_t nu = params.GetParameters().GetTerminateBitsize();
    std::vector<block> uv_prev(1ULL<<nu), uv_next(1ULL<<nu);
    eval.OnlineSetUp(party_id, base);
    rss.OnlineSetUp(party_id, base+"prf");

    // Evaluate
    RepShare64 result_sh; 
    eval.Evaluate(chls, key, uv_prev, uv_next, RepShareView64(db_sh), idx_sh, result_sh);

    // Open the result to a clear value (for testing)
    uint64_t local_res = 0; rss.Open(chls, result_sh, local_res);
    Logger::DebugLog(LOC, "result=" + ToString(local_res));
  }; 
};

// Configure and run; party_id may be fixed via CLI
int party_id = cmd.isSet("party") ? cmd.get<int>("party") : -1;
net.AutoConfigure(party_id, MakeTask(0), MakeTask(1), MakeTask(2));
net.WaitForCompletion();
```

### 3. シェア・鍵の読み取り方（各自のパスから）

* 鍵: `KeyIo.LoadKey(base+"ringoakey_d{d}_{party}", key)`
* DBシェア: `ShareIo.LoadShare(base+"ringoadb_d{d}_{party}", db_sh)`
* indexシェア: `ShareIo.LoadShare(base+"ringoaidx_d{d}_{party}", idx_sh)`

### 4. プロトコルの実行方法

* `eval.OnlineSetUp(...)` と `rss.OnlineSetUp(...)` を呼んだ後、
* `eval.Evaluate(...)` で結果シェア `result_sh` を得る。
* 検証時は `rss.Open(...)` で平文に開示（本番では不要）。
