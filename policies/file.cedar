// ═══════════════════════════════════════════════════════
// Sondera – File-Specific Governance Policies
// ═══════════════════════════════════════════════════════
//
// Extension-aware policies that combine information flow
// control (IFC), YARA signature detection, and secure code
// generation policy categories (OWASP/CWE) to enforce
// fine-grained governance on file operations.
//
// Builds on the base policies in base.cedar. These policies
// target specific file types where particular threat classes
// are most relevant — a SQL injection finding in a .sql file
// is far more actionable than in a .md file.
//
// ─── Available Context ──────────────────────────────────
//
//   FileRead / FileWrite / FileEdit / FileDelete (pre-exec):
//     resource  = File { label: Label }
//     context   = { workspace, signature, policy, label,
//                   path: String, operation: String }
//
//   FileOperationResult (post-exec):
//     resource  = Trajectory { step_count, label, taints }
//     context   = { workspace, signature, policy, label,
//                   path: String, content: String }
//
//   policy.violations contains Secure Code Generation (SC)
//   category codes from OWASP/CWE evaluation:
//     SC2 = Injection        (CWE-78/89/79, OWASP A03:2021)
//     SC3 = Secrets Exposure (CWE-798/200, OWASP A02:2021)
//     SC4 = Path Traversal   (CWE-22,      OWASP A01:2021)
//     SC5 = Insecure Deser.  (CWE-502,     OWASP A08:2021)
//     SC6 = Weak Crypto      (CWE-327/330, OWASP A02:2021)
//     SC7 = Broken AuthZ     (CWE-284/862, OWASP A01:2021)

// ═══════════════════════════════════════════════════════
// §1  Information Flow Control – Label-Based Guards
// ═══════════════════════════════════════════════════════
//
// Enforce the "no write down" rule from the Bell-LaPadula
// model: content classified at a higher sensitivity level
// must not flow to a file entity at a lower level. This
// prevents data spillage — e.g. an agent that has seen
// highly confidential data cannot write it into a public
// or internal file.

@id("forbid-file-write-hc-to-public")
@description("IFC: block writing highly confidential content to a file labeled Public — prevents data spillage.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    resource.label == Label::"Public"
};

@id("forbid-file-write-hc-to-internal")
@description("IFC: block writing highly confidential content to a file labeled Internal — prevents data spillage.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    resource.label == Label::"Internal"
};

@id("forbid-file-write-confidential-to-public")
@description("IFC: block writing confidential content to a file labeled Public — prevents data spillage.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.label == Label::"Confidential" &&
    resource.label == Label::"Public"
};

// ─── IFC: taint-aware post-read guards ───
//
// After a file read completes, the trajectory inherits
// the file's sensitivity label. These policies block
// further processing when the trajectory is already
// tainted with exfiltration indicators — reading more
// sensitive files at that point would expand the blast
// radius.

@id("forbid-file-result-hc-on-exfil-tainted-trajectory")
@description("IFC: block highly confidential file read results when trajectory is tainted with exfiltration — limits blast radius.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    resource.taints.contains(Taint::"exfiltration")
};

@id("forbid-file-result-confidential-on-exfil-tainted-trajectory")
@description("IFC: block confidential file read results when trajectory is tainted with exfiltration.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    context.label == Label::"Confidential" &&
    resource.taints.contains(Taint::"exfiltration")
};

// ═══════════════════════════════════════════════════════
// §2  Credential & Secret File Guards
// ═══════════════════════════════════════════════════════
//
// Targeted protection for file types that inherently
// carry secrets or credentials. YARA signatures provide
// the detection; these policies scope enforcement to the
// file extensions where the risk is highest.

// ─── Private keys & keystores ───

@id("forbid-private-key-read")
@description("Block reading private key files — agent should never access raw key material.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*.pem" ||
    context.path like "*.key" ||
    context.path like "*.p12" ||
    context.path like "*.pfx" ||
    context.path like "*.jks"
};

@id("forbid-private-key-write")
@description("Block writing private key files — agent should not generate or overwrite key material.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.pem" ||
    context.path like "*.key" ||
    context.path like "*.p12" ||
    context.path like "*.pfx" ||
    context.path like "*.jks"
};

// ─── Environment & config files with secrets ───

@id("forbid-env-file-write-with-secrets")
@description("Block writing secrets into .env files — detected by YARA secrets_detection rules.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.env" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-env-file-write-with-credentials")
@description("Block writing credentials into .env files — detected by YARA credential_access rules.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.env" &&
    context.signature.categories.contains("credential_access")
};

// ─── Secrets in source code ───

@id("forbid-source-write-secrets-python")
@description("Block writing secrets into Python source files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-javascript")
@description("Block writing secrets into JavaScript/TypeScript source files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-go")
@description("Block writing secrets into Go source files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.go" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-rust")
@description("Block writing secrets into Rust source files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rs" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-java")
@description("Block writing secrets into Java source files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.signature.categories.contains("secrets_detection")
};

// ─── Secrets in config serialization formats ───

@id("forbid-config-write-secrets-yaml")
@description("Block writing secrets into YAML config files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-config-write-secrets-json")
@description("Block writing secrets into JSON config files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.json" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-config-write-secrets-toml")
@description("Block writing secrets into TOML config files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.toml" &&
    context.signature.categories.contains("secrets_detection")
};

// ═══════════════════════════════════════════════════════
// §3  Obfuscation Detection – Script & Shell Files
// ═══════════════════════════════════════════════════════
//
// Obfuscated content in executable files is a strong
// indicator of malicious intent. Block writes to scripts
// and shell files when obfuscation YARA rules fire.

@id("forbid-script-write-obfuscation")
@description("Block writing obfuscated content into shell scripts.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.sh" || context.path like "*.bash" ||
     context.path like "*.zsh") &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-python-write-obfuscation")
@description("Block writing obfuscated content into Python files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-js-write-obfuscation")
@description("Block writing obfuscated content into JavaScript/TypeScript files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-php-write-obfuscation")
@description("Block writing obfuscated content into PHP files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.php" &&
    context.signature.categories.contains("obfuscation")
};

// ═══════════════════════════════════════════════════════
// §4  SC2 – Injection (CWE-78/89/79, OWASP A03:2021)
// ═══════════════════════════════════════════════════════
//
// Block generated code with injection vulnerabilities in
// file types where those flaws are exploitable: SQL files,
// server-side languages, and web templates.

@id("forbid-injection-sql")
@description("SC2: block writing SQL files with injection vulnerabilities (unsanitized query construction).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.sql" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-python")
@description("SC2: block writing Python files with injection vulnerabilities (shell/SQL/eval injection).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-javascript")
@description("SC2: block writing JavaScript/TypeScript files with injection vulnerabilities (XSS, eval, template injection).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-php")
@description("SC2: block writing PHP files with injection vulnerabilities (shell_exec, SQL concat, XSS).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.php" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-go")
@description("SC2: block writing Go files with injection vulnerabilities (os/exec, sql.Query with fmt.Sprintf).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-ruby")
@description("SC2: block writing Ruby files with injection vulnerabilities (system, backticks, ERB injection).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rb" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-rust")
@description("SC2: block writing Rust files with injection vulnerabilities (Command::new with unsanitized input).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-java")
@description("SC2: block writing Java files with injection vulnerabilities (ProcessBuilder, JDBC concat).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-html-templates")
@description("SC2: block writing HTML template files with XSS vulnerabilities (unescaped interpolation).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.html" || context.path like "*.svelte" ||
     context.path like "*.vue" || context.path like "*.ejs" ||
     context.path like "*.hbs") &&
    context.policy.violations.contains("SC2")
};

// ═══════════════════════════════════════════════════════
// §5  SC3 – Secrets Exposure (CWE-798/200, OWASP A02:2021)
// ═══════════════════════════════════════════════════════
//
// Block generated code that hardcodes secrets in config
// and infrastructure files. Distinct from §2 signature-
// based detection — these fire on the policy model's
// semantic analysis of the code, catching patterns like
// `password = "hunter2"` that signatures may miss.

@id("forbid-secrets-exposure-env")
@description("SC3: block writing .env files with hardcoded secrets (should use vault/secret manager references).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.env" &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-yaml-config")
@description("SC3: block writing YAML config files with hardcoded secrets.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-docker")
@description("SC3: block writing Dockerfiles with hardcoded secrets (ARG/ENV with credentials).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*Dockerfile" || context.path like "*.dockerfile" ||
     context.path like "*docker-compose*.yml" || context.path like "*docker-compose*.yaml") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-terraform")
@description("SC3: block writing Terraform/IaC files with hardcoded secrets.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.tf" || context.path like "*.tfvars") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-ci-config")
@description("SC3: block writing CI/CD config files with hardcoded secrets.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.github/workflows/*.yml" ||
     context.path like "*.github/workflows/*.yaml" ||
     context.path like "*.gitlab-ci.yml" ||
     context.path like "*Jenkinsfile") &&
    context.policy.violations.contains("SC3")
};

// ═══════════════════════════════════════════════════════
// §6  SC5 – Insecure Deserialization (CWE-502, OWASP A08)
// ═══════════════════════════════════════════════════════
//
// Block generated code that uses unsafe deserialization
// on untrusted input. Targets languages with known-dangerous
// deserializers: Python (pickle, yaml.load), Ruby (Marshal),
// Java (ObjectInputStream), PHP (unserialize).

@id("forbid-insecure-deser-python")
@description("SC5: block writing Python files with insecure deserialization (pickle.load, yaml.load without SafeLoader).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-yaml")
@description("SC5: block writing YAML files with unsafe loader directives.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-ruby")
@description("SC5: block writing Ruby files with insecure deserialization (Marshal.load, YAML.load on untrusted).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rb" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-java")
@description("SC5: block writing Java files with insecure deserialization (ObjectInputStream on untrusted).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-php")
@description("SC5: block writing PHP files with insecure deserialization (unserialize on user input).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.php" &&
    context.policy.violations.contains("SC5")
};

// ═══════════════════════════════════════════════════════
// §7  SC6 – Weak Cryptography (CWE-327/330, OWASP A02)
// ═══════════════════════════════════════════════════════
//
// Block generated code that uses broken or weak crypto:
// MD5/SHA-1 for hashing, DES/RC4/ECB for encryption,
// Math.random()/random.randint() for security tokens.

@id("forbid-weak-crypto-python")
@description("SC6: block writing Python files with weak cryptography (md5, sha1, random for tokens).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-javascript")
@description("SC6: block writing JavaScript/TypeScript files with weak cryptography (Math.random for tokens, createHash('md5')).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-go")
@description("SC6: block writing Go files with weak cryptography (crypto/md5, crypto/des, math/rand for tokens).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-rust")
@description("SC6: block writing Rust files with weak cryptography (md5 crate for auth, rand::thread_rng for tokens).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-java")
@description("SC6: block writing Java files with weak cryptography (MessageDigest MD5/SHA1, DES, ECB mode).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC6")
};

// ═══════════════════════════════════════════════════════
// §8  SC7 – Broken Access Control (CWE-284/862, OWASP A01)
// ═══════════════════════════════════════════════════════
//
// Block generated code with missing authentication or
// authorization checks on endpoints that modify state.
// Targets server-side languages and API framework files.

@id("forbid-broken-authz-python")
@description("SC7: block writing Python API files with broken access control (unprotected endpoints, missing auth decorators).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-javascript")
@description("SC7: block writing JavaScript/TypeScript API files with broken access control (unprotected routes, missing middleware).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-go")
@description("SC7: block writing Go API files with broken access control (handlers without auth middleware).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-java")
@description("SC7: block writing Java API files with broken access control (missing @PreAuthorize, unprotected controllers).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-rust")
@description("SC7: block writing Rust API files with broken access control (handlers without auth extractors).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC7")
};

// ═══════════════════════════════════════════════════════
// §9  SC4 – Path Traversal (CWE-22, OWASP A01:2021)
// ═══════════════════════════════════════════════════════
//
// Block generated code that constructs file paths from
// user input without canonicalization or base-directory
// validation. Applies broadly to all server-side languages.

@id("forbid-path-traversal-python")
@description("SC4: block writing Python files with path traversal vulnerabilities (open() with user-controlled paths).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-javascript")
@description("SC4: block writing JavaScript/TypeScript files with path traversal vulnerabilities (fs.readFile with user paths).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-go")
@description("SC4: block writing Go files with path traversal vulnerabilities (os.Open with user paths).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-java")
@description("SC4: block writing Java files with path traversal vulnerabilities (new File with user paths).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-rust")
@description("SC4: block writing Rust files with path traversal vulnerabilities (std::fs with user paths).")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC4")
};

// ═══════════════════════════════════════════════════════
// §10  Post-Read Guards – Indirect Injection via Files
// ═══════════════════════════════════════════════════════
//
// When the agent reads a file, the content enters the
// conversation context. Malicious content embedded in
// data files or configs can act as indirect prompt
// injection. These policies guard specific file types
// that are commonly used as injection vectors.

@id("forbid-file-result-injection-yaml")
@description("Block YAML file content containing prompt injection — prevents indirect injection via config files.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-json")
@description("Block JSON file content containing prompt injection — prevents indirect injection via data files.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    context.path like "*.json" &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-markdown")
@description("Block Markdown file content containing prompt injection — prevents indirect injection via documentation.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    (context.path like "*.md" || context.path like "*.mdx") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-csv")
@description("Block CSV/TSV file content containing prompt injection — prevents indirect injection via data imports.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    (context.path like "*.csv" || context.path like "*.tsv") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
