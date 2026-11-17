# zero-pii-redactor (日本語ドキュメント)

ログ、AIプロンプト、テレメトリ、エッジ環境向けの高速な個人情報（PII）マスキング・トークナイザー・仮名化ライブラリ。組み込み検出器は入力サイズを制限し、外部ランタイム依存なしで動作します。

## トークンと仮名化値の互換性

- 可逆トークンはHKDF-SHA-256を使う `pii_tok_v2_` 形式になり、このバージョンは旧形式を拒否します。旧トークンを保持する必要がある場合は、信頼できる旧バージョンで復号してから、管理された移行で再トークン化してください。トークン用シークレットはUTF-8で32バイト以上が必要です。
- 仮名化はドメイン分離したHMAC-SHA-256になりました。既存の仮名化値は変わり、元の識別子とソルトなしでは移行できません。既存データとの結合や分析への影響を計画してください。

---

## 主な特長

1. **組み込み検出器の入力制限**:
   - 1 MiBを超える入力を拒否し、組み込み検出器は長さを制限したパターンで走査します。利用者が渡す正規表現はJavaScript側で実行時間を制限できないため、信頼できるパターンだけを指定してください。悪意あるパターンやバックトラッキングするパターンはReDoSを起こす可能性があります。
2. **Luhn アルゴリズムによるクレジットカード番号検証**:
   - モジュロ10チェックサムを検証し、ランダムな16桁の数値による誤検知を排除。
3. **深い JSON オブジェクトの再帰的サニタイズ**:
   - ネストしたオブジェクトや配列、機密キー（`password`, `apiKey`, `secret` 等）を自動的にスクラビング。
4. **柔軟なマスキング & 仮名化モード**:
   - `mask`（部分マスク）、`replace`（置換タグ）、`pseudonymize`（HMAC-SHA-256による鍵付き決定論的仮名化）。
5. **可逆な暗号化トークナイザー**:
   - AES-GCM による安全な一時トークン化（`tokenize` / `detokenize`）。

---

## 関連エッジセキュリティパッケージ群

- [wasm-crypto-hash](https://github.com/takao-dev/wasm-crypto-hash): 超高速 WebAssembly & WebCrypto 暗号化スイート (SHA-2/3, BLAKE3, PQC, Argon2, TOTP, BIP-39)
- [edge-rate-limiter](https://github.com/takao-dev/edge-rate-limiter): 外部依存ゼロの固定/スライド窓型レートリミッター（ソルト付き匿名化対応）
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): タイミング攻撃耐性を持つ WebCrypto ベースの JWT & クレーム暗号化スイート
- [edge-session-crypto](https://github.com/takao-dev/edge-session-crypto): AES-GCM と鍵ローテーションを備えたステートレス暗号化クッキーセッション管理
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): AES-GCM & HMAC による改ざん検知機能付きセキュアKVストレージ
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): 暗号論的ハッシュチェーンによる改ざん耐性監査ログ記録

---

## ライセンス

MIT License
