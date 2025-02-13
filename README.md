
Rustfuzz は、Web アプリケーションや API のセキュリティテストを行うためのファジングツールです。
XSS、SQL インジェクション、OS コマンドインジェクション、NoSQL インジェクション、LDAP インジェクション、JSON インジェクション、CRLF インジェクション、Unicode インジェクション、XPath インジェクション、XSLT インジェクション、XXE など、ほとんどの脆弱性をテストできます。

特徴
複数の脆弱性をテスト: 一般的な Web 脆弱性を幅広くカバー
Rustによる高速動作: 非同期処理を活用し、効率的にファジング
簡単な使用方法：コマンドラインから対象URLを指定するだけ
インストール
Rustfuzz を使うには、Rust の環境が必要です。

1. Rustのインストール
Rustがインストールされていない場合は、Rust公式サイトからインストールしてください。

シュ

コピーする

編集する
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
2. Rustfuzz のビルド
シュ

コピーする

編集する
git clone https://github.com/your-repository/rustfuzz.git
cd rustfuzz
cargo build --release
使い方
基本的な使用方法
シュ

コピーする

編集する
./target/release/rustfuzz <ターゲットURL>
例:

シュ

コピーする

編集する
./target/release/rustfuzz http://example.com/login
検出可能な脆弱性
Rustfuzz は以下の脆弱性をテストできます。

脆弱性	説明
クロススレッド	クロスサイトスクリプティング
SQLインジェクション	SQL インジェクション
OSコマンドインジェクション	OSコマンドインジェクション
NoSQLインジェクション	NoSQLインジェクション
LDAP インジェクション	LDAP インジェクション
JSONインジェクション	JSON インジェクション
CRLFインジェクション	CRLF インジェクション
ユニコードインジェクション	Unicodeを用いたバイパス
XPathインジェクション	XPath インジェクション
XSLTインジェクション	XSLTインジェクション
XXE	XML 外部エンティティ攻撃
各テストの詳細な実行方法
特定の脆弱性をテストする場合は、以下のように指定してください。

1. XSS、SQL、OS コマンドインジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz http://example.com/login
2. NoSQL インジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --nosql http://example.com/api/login
3. LDAP インジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --ldap ldap://example.com
4. JSONインジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --json http://example.com/api
5. CRLFインジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --crlf http://example.com
6. Unicode インジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --unicode http://example.com
7. XPath インジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --xpath "users.xml" "/users/user"
8. XSLT インジェクションのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --xslt "stylesheet.xsl" "data.xml"
9. XXEのテスト
シュ

コピーする

編集する
./target/release/rustfuzz --xxe "data.xml"
開発
Rustfuzz を開発するには、以下の手順を実行してください。

依存関係のインストール
シュ

コピーする

編集する
cargo build
コード実行
シュ

コピーする

編集する
cargo run -- http://example.com
コードフォーマット
シュ

コピーする

編集する
cargo fmt
テストソリューション
シュ

コピーする

編集する
cargo test
ライセンス
このプロジェクトはMITライセンスの下で提供されます。

どうでしょうか？ 😊






あなた:
README.mdを書いてますか
チャットGPT:
OK！このツールの目的や使い方をREADMEにまとめますね。Rustで書いた多種多様なインジェクション脆弱性をテストするツールですので、それに沿った構成で書きます。

🚀 インジェクション ファザー (Rust)
Injection Fuzzerは、Webアプリケーションの各種インジェクション脆弱性をテストするためのツールです。
Rust製で、以下のインジェクション攻撃に対応しています。

✅ SQL インジェクション (SQLi)
✅ クロスサイトスクリプティング (XSS)
✅ OSコマンドインジェクション
✅ NoSQLインジェクション
✅ サーバーサイドテンプレートインジェクション (SSTI / CSTI)
✅ HTTP ヘッダーインジェクション
✅ LDAP インジェクション
✅ JSON インジェクション
✅ CRLF インジェクション
✅ Unicode インジェクション
✅ XPath インジェクション
✅ XSLT インジェクション
✅ XML 外部エンティティ (XXE)
📦 インストール
必要な環境
Rust（公式サイトからインストールしてください）
cargo（Rustに付属）
クローンとビルド
シュ

コピーする

編集する
git clone https://github.com/yourusername/injection-fuzzer.git
cd injection-fuzzer
cargo build --release
🚀 使い方
基本的な実行方法
シュ

コピーする

編集する
./target/release/injection-fuzzer <ターゲットURL>
例、ローカルのWebアプリ ( http://localhost:8080/login) をテストする場合:

シュ

コピーする

編集する
./target/release/injection-fuzzer http://localhost:8080/login
特定の噴射タイプをテストする
オプションを指定して特定のインジェクション攻撃をテストできます。

シュ

コピーする

編集する
./target/release/injection-fuzzer --xss http://example.com
./target/release/injection-fuzzer --sqli http://example.com
./target/release/injection-fuzzer --ldap http://ldap.example.com
🛠サポートしているペイロード
各インジェクションのペイロードはsrc/payloads.rsに定義されています。カスタム
ペイロードを追加する場合は、このファイルを編集してください。

📜 例: SQL インジェクション テスト
目標がhttp://example.com/loginで、パラメータがusernameあるpassword場合:

シュ

コピーする

編集する
./target/release/injection-fuzzer --sqli http://example.com/login
それでは、ツールは以下のようなペイロードを試してみます。

SQL文

コピーする

編集する
[*] Testing SQLi: ' OR '1'='1
[*] Testing SQLi: 1' OR '1'='1' --
[*] Testing SQLi: ' UNION SELECT NULL,NULL--
...
応答が異常な場合、警告を出力します。

pgsql

コピーする

編集する
[!] Possible SQL Injection found! Payload: ' OR '1'='1
⚠️注意
このツールは教育・検証目的でのみ使用してください。
許可なく第三者のシステムに対して使用すると慎重になる可能性があります。
の管理する環境や、適切な許可を得た環境でのみ実行してください。
📜 ライセンス
MITライセンス

✨ 貢献
バグ報告や機能の提案は問題点へお願いします！

