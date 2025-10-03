# RingOA-Template

三者間での Oblivious Access を実現した **RingOA プロトコル** および基本的な秘密計算プロトコルを実装した **C++ テンプレートリポジトリ**です。

---

## 準備

### GitHub アカウントの権限設定
- 清水研 GitHub 組織の `cBioLab` メンバーである必要があります。  
- `cBioLab` 内の **mpc チーム** に所属している必要があります。  
- `u-tmk` アカウント配下の `RingOA-dev` リポジトリの Collaborators に追加されている必要があります。  

---

## セットアップ & ビルド

```bash
# リポジトリを取得
git clone git@github.com:cBioLab/RingOA-Template.git
cd RingOA-Template

# 初回セットアップ（thirdparty を Release モードでビルド）
python build.py --setup

# プロジェクト本体をビルド
python build.py
```

---

## 実行方法

ビルドが成功すると `out/build/linux/bin/` 以下にバイナリが生成されます。  
以下のコマンドでサンプルを実行できます。

```bash
./out/build/linux/bin/example
```

---

## セットアップ & ビルドの種類

このリポジトリでは、`build.py` を使って **依存ライブラリ (thirdparty)** と **プロジェクト本体** をビルドします。  
よく使うコマンドは以下の通りです。

### セットアップ（依存ライブラリのビルド）

- すべての thirdparty をビルド（初回や環境構築時）
  ```bash
  python build.py --setup
  ```

- RingOA のみをビルド（RingOA に変更があったとき）
  ```bash
  rm -rf thirdparty/RingOA/out/build/linux
  python build.py --setup-ringoa
  ```

- Debug モードで RingOA をビルド（開発・デバッグ用）
  ```bash
  rm -rf thirdparty/RingOA/out/build/linux
  python build.py --setup-ringoa --debug
  ```

- CMake オプションを追加してビルド（例: ログレベル指定）
  ```bash
  rm -rf thirdparty/RingOA/out/build/linux
  python build.py --setup-ringoa --debug -- -DLOG_LEVEL=6
  ```

---

### プロジェクト本体のビルド

- **通常のビルド（Release モード）**
  ```bash
  python build.py
  ```

- **Debug モードでビルド**
  ```bash
  python build.py --debug
  ```

> Note: ソースコードを変更した場合は、再度 python build.py を実行してビルドを更新してください。
> もしビルドを実行しても反映されない場合は、以下のコマンドで一度ビルドディレクトリを削除してから再度ビルドしてください。
> ```bash
> rm -rf out/build/linux
> python build.py
> ```
> これは CMake のキャッシュが原因で変更が反映されない場合があるためです。

---
  
### ヘルプ表示

詳細なオプションは以下で確認できます。

```bash
python build.py --help
```

---

## RingOAのログレベル

`-DLOG_LEVEL=N` でビルド時のログ出力レベルを指定できます。  
数字が大きいほど詳細なログが出力されます。

| レベル | 定数              | 説明                         |
| ------ | ----------------- | ---------------------------- |
| 0      | `LOG_LEVEL_NONE`  | ログを出力しない             |
| 1      | `LOG_LEVEL_FATAL` | 致命的なエラーのみ出力       |
| 2      | `LOG_LEVEL_ERROR` | エラーを出力                 |
| 3      | `LOG_LEVEL_WARN`  | 警告を出力                   |
| 4      | `LOG_LEVEL_INFO`  | 情報メッセージ（デフォルト） |
| 5      | `LOG_LEVEL_DEBUG` | デバッグ用の詳細ログを出力   |
| 6      | `LOG_LEVEL_TRACE` | トレースレベル（最も詳細）   |

例:  

```bash
python build.py --setup-ringoa --debug -- -DLOG_LEVEL=6
```

この場合、`TRACE` まで全てのログが出力されます。

---

## 実装の追加方法

- サンプルを追加する場合は `example/` ディレクトリにソースコードを追加し、`example/CMakeLists.txt` にターゲットを記述してください。  
- 新しいディレクトリを作成してモジュールを追加する場合は、プロジェクトの `CMakeLists.txt` に `add_subdirectory(your_directory)` を追記してください。

---


## ディレクトリ構成

```bash
RingOA-Template/
├── CMakeLists.txt        # プロジェクト全体の CMake 設定
├── build.py              # セットアップ & ビルドスクリプト
├── example/              # サンプルコード
│   ├── CMakeLists.txt    # サンプル用 CMake 設定
│   └── main.cpp          # サンプルのエントリーポイント
└── thirdparty/           # 外部依存ライブラリの管理
    ├── getCryptoTools.py # cryptoTools の取得スクリプト
    └── getRingOA.py      # RingOA 実装の取得スクリプト
```

---

## スクリプトの説明

### 1. `build.py`
プロジェクト全体のビルド・インストール制御スクリプト。  
依存ライブラリのセットアップや、Release/Debug ビルドの切り替え、インストール処理をまとめて行います。

### 2. `thirdparty/getRingOA.py`

RingOA ライブラリ本体の取得・更新・ビルドを行うスクリプト。

1. cryptoTools & Boost の準備
   `thirdparty/getCryptoTools.py` を呼び出し、cryptoTools と Boost を取得・セットアップ。  

2. RingOA の取得  
   - 未取得なら `git clone git@github.com:u-tmk/RingOA-dev.git`  
   - 既に存在する場合は `git pull` により更新。  
   - さらに `git submodule update --init --recursive` でサブモジュールを更新。  

3. RingOA のビルド & インストール  
   - RingOA リポジトリ内の `build.py` を呼び出してビルド・インストール。  
   - インストール先は `thirdparty/unix/` 以下。  
   - `--debug`, `--sudo` フラグを利用可能。  

### 3. `thirdparty/getCryptoTools.py`

cryptoTools および依存ライブラリ (Boost) を取得・ビルドするスクリプト。

1. cryptoTools の取得 & バージョン固定  
   - `https://github.com/ladnir/cryptoTools.git` をクローン。  
   - 特定のコミット (`2bf5fe84...`) にチェックアウト。  
   - サブモジュールを初期化。  

2. 依存ライブラリのセットアップ  
   - Boost をセットアップ (`--boost`)  

3. cryptoTools のビルド  
   - CMake オプションを付与してビルド。  
   - インストール先は `thirdparty/unix/` 以下。  

---
