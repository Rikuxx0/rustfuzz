# Rustfuzz

This tool is a Rust-based script designed for testing various injection vulnerabilities in web applications. It includes modules for testing XSS, SQL injection, NoSQL injection, OS command injection, CRLF injection, LDAP injection, XPath injection, XSLT injection, XXE vulnerabilities, and more.


## Requirements
- Rust
- Cargo


## 1 Install Rust
Install the Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 2 Build Rustfuzz
```bash
git clone https://github.com/your-repository/rustfuzz.git
cd rustfuzz
cargo build --release
```

## Usage
Basic Usage
```bash
./target/release/rustfuzz <target_URL>
```

Example:
```bash
/target/release/rustfuzz http://example.com/login
```

You can check various Injection tests and detect Injection vulnerbilities.
This is the same to previous Python-based FuzzingTool.

## Notes
- Ensure you have proper authorization before testing a target system.
- Use responsibly and only for ethical penetration testing.

