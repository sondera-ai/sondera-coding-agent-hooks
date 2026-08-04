/*
 * Secrets Detection Rules
 *
 * Detects leaked secrets and credentials in AI agent interactions including:
 * - API keys and tokens
 * - Cloud provider credentials
 * - Private keys
 * - Database credentials
 * - OAuth tokens
 * - Encryption keys
 */

rule secrets_api_keys_generic {
    meta:
        description = "Detects generic API key patterns"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Generic API key patterns
        $api1 = /api[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $api2 = /apikey['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $api3 = /api[_-]?secret['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $api4 = /api[_-]?token['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase

        // Access key patterns
        $access1 = /access[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $access2 = /secret[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase

    condition:
        any of them
}

rule secrets_aws_credentials {
    meta:
        description = "Detects AWS credentials"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // AWS Access Key ID (20 chars starting with AKIA)
        $aws_key = /AKIA[0-9A-Z]{16}/

        // AWS Secret Access Key (40 chars base64-like)
        $aws_secret = /aws_secret_access_key['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{40}/ nocase

        // AWS Session Token
        $aws_token = /aws_session_token['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{100,}/ nocase

        // AWS credentials file pattern
        $aws_creds = "[default]"
        $aws_creds2 = "aws_access_key_id"

    condition:
        $aws_key or $aws_secret or $aws_token or ($aws_creds and $aws_creds2)
}

rule secrets_gcp_credentials {
    meta:
        description = "Detects Google Cloud Platform credentials"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // GCP Service Account Key (JSON format)
        $gcp_json = /"type"\s*:\s*"service_account"/
        $gcp_json2 = /"private_key"/

        $gcp_key = /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/

        // GCP API Key
        $gcp_api = /AIza[0-9A-Za-z_\-]{35}/

        // GCP OAuth Client Secret
        $gcp_oauth = /"client_secret"\s*:\s*"[A-Za-z0-9_\-]{20,}"/

    condition:
        ($gcp_json and $gcp_json2) or $gcp_key or $gcp_api or $gcp_oauth
}

rule secrets_azure_credentials {
    meta:
        description = "Detects Microsoft Azure credentials"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Azure Storage Account Key
        $azure_storage = /DefaultEndpointsProtocol=https.*AccountKey=[A-Za-z0-9\/\+=]{88}/

        // Azure Service Principal
        $azure_sp_id = /"appId"\s*:\s*"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"/
        $azure_sp_secret = /"password"\s*:\s*"[A-Za-z0-9~\.\-]{20,}"/

        // Azure Subscription Key
        $azure_sub = /Ocp-Apim-Subscription-Key['"\s]*[:=]['"\s]*[a-f0-9]{32}/ nocase

    condition:
        any of them
}

rule secrets_private_keys {
    meta:
        description = "Detects private cryptographic keys"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // RSA Private Key
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"

        // EC Private Key
        $ec = "-----BEGIN EC PRIVATE KEY-----"

        // Generic Private Key
        $private = "-----BEGIN PRIVATE KEY-----"

        // Encrypted Private Key
        $encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----"

        // OpenSSH Private Key
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"

        // DSA Private Key
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"

    condition:
        any of them
}

rule secrets_github_tokens {
    meta:
        description = "Detects GitHub tokens and credentials"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // GitHub Personal Access Token (classic)
        $gh_pat_classic = /ghp_[0-9A-Za-z]{36}/

        // GitHub OAuth Access Token
        $gh_oauth = /gho_[0-9A-Za-z]{36}/

        // GitHub User-to-Server Token
        $gh_user = /ghu_[0-9A-Za-z]{36}/

        // GitHub Server-to-Server Token
        $gh_server = /ghs_[0-9A-Za-z]{36}/

        // GitHub Refresh Token
        $gh_refresh = /ghr_[0-9A-Za-z]{36}/

    condition:
        any of them
}

rule secrets_slack_tokens {
    meta:
        description = "Detects Slack tokens and webhooks"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Slack Bot Token
        $slack_bot = /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/

        // Slack User Token
        $slack_user = /xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/

        // Slack Webhook
        $slack_webhook = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/

        // Slack App Token
        $slack_app = /xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]{64}/

    condition:
        any of them
}

rule secrets_generic_database_credentials {
    meta:
        description = "Detects generic database connection strings and credentials"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Generic database password
        $db_pass = /db[_-]?password['"\s]*[:=]['"\s]*[^\s'"]{8,}/ nocase
        $password = /password['"\s]*[:=]['"\s]*[^\s'"]{8,}/
        $password2 = "postgres"
        $password3 = "mysql"
        $password4 = "mongodb"

    condition:
        $db_pass or
        $password and ($password2 or $password3 or $password4)
}

rule secrets_database_credentials {
    meta:
        description = "Detects database connection strings and credentials"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // MongoDB connection string
        $mongodb = /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/

        // PostgreSQL connection string (including SQLAlchemy driver suffixes like +asyncpg)
        $postgres = /postgres(ql)?(\+\w+)?:\/\/[^:]+:[^@]+@/

        // MySQL connection string
        $mysql = /mysql:\/\/[^:]+:[^@]+@/

        // Redis connection string with password
        $redis = /redis:\/\/:[^@]+@/

        // Well-known default/dev credentials in connection strings (false positives)
        $dev_pg = /:\/\/postgres:postgres@/
        $dev_root = /:\/\/root:root@/
        $dev_admin = /:\/\/admin:admin@/
        $dev_user_pass = /:\/\/user:password@/ nocase
        $dev_root_pass = /:\/\/root:password@/ nocase
        $dev_admin_pass = /:\/\/admin:password@/ nocase
        $dev_changeme = /:\/\/[^:]+:changeme@/ nocase

    condition:
        any of ($mongodb, $postgres, $mysql, $redis) and
        not any of ($dev_*)
}

rule secrets_jwt_tokens {
    meta:
        description = "Detects JWT tokens that may contain sensitive information"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // JWT token pattern (3 base64 segments separated by dots)
        $jwt = /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/

    condition:
        $jwt and filesize < 10KB // Only flag if in small content (not full JWT libraries)
}

rule secrets_stripe_keys {
    meta:
        description = "Detects Stripe API keys"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Stripe Secret Key
        $stripe_secret = /sk_(test|live)_[0-9A-Za-z]{24,}/

        // Stripe Restricted Key
        $stripe_restricted = /rk_(test|live)_[0-9A-Za-z]{24,}/

        // Stripe Publishable Key (less sensitive but still flagged)
        $stripe_pub = /pk_(test|live)_[0-9A-Za-z]{24,}/

    condition:
        any of ($stripe_secret, $stripe_restricted) or
        (2 of them) // Flag if multiple Stripe keys present
}

rule secrets_twilio_credentials {
    meta:
        description = "Detects Twilio API credentials"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Twilio Account SID
        $twilio_sid = /AC[a-f0-9]{32}/

        // Twilio Auth Token
        $twilio_token = /twilio[_-]?auth[_-]?token['"\s]*[:=]['"\s]*[a-f0-9]{32}/ nocase

        // Twilio API Key
        $twilio_key = /SK[a-f0-9]{32}/

    condition:
        any of them
}

rule secrets_sendgrid_keys {
    meta:
        description = "Detects SendGrid API keys"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $sendgrid = /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/

    condition:
        $sendgrid
}

rule secrets_openai_keys {
    meta:
        description = "Detects OpenAI API keys"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // OpenAI API Key
        $openai = /sk-[A-Za-z0-9]{48}/

        // OpenAI Organization ID
        $openai_org = /org-[A-Za-z0-9]{24}/

    condition:
        any of them
}

rule secrets_anthropic_keys {
    meta:
        description = "Detects Anthropic API keys"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $anthropic = /sk-ant-[A-Za-z0-9_\-]{95,}/

    condition:
        $anthropic
}

rule secrets_generic_passwords {
    meta:
        description = "Detects generic password patterns in structured data"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // JSON/YAML password fields with values (quoted — 8+ chars)
        $pass1 = /"password"\s*:\s*"[^\s"]{8,}"/ nocase
        $pass2 = /'password'\s*:\s*'[^\s']{8,}'/ nocase

        // Unquoted password values — split into complexity-based patterns to
        // filter pure-alpha short defaults (postgres, password, changeme)
        // 11+ chars (any composition)
        $pass3_long = /password\s*[:=]\s*[^\s]{11,}/ nocase
        // 8+ chars containing at least one digit
        $pass3_digit = /password\s*[:=]\s*[^\s]*[0-9][^\s]*/ nocase
        // Contains a special character AND first byte is not `$` or `{` —
        // excludes template expressions like `${{ ... }}`, `${VAR}`, `{{ ... }}`
        // whose leading char would be a special. The any-length / any-position
        // variant lives in `secrets_generic_passwords_loose` at info severity.
        $pass3_special = /password\s*[:=]\s*[^\s$\{][^\s]*[^A-Za-z0-9\s][^\s]*/ nocase

        // Common password variable names (quoted values, 8+ chars)
        $var1 = /PASSWORD\s*=\s*["'][^\s"']{8,}["']/
        $var2 = /PASS\s*=\s*["'][^\s"']{8,}["']/
        $var3 = /SECRET\s*=\s*["'][^\s"']{8,}["']/

    condition:
        any of them
}

rule secrets_generic_template_passwords {
    meta:
        description = "Detects passwords bound to CI/CD template expressions (${{ ... }}, ${VAR}, $VAR, $(var), {{ var }}). High-volume signal — flagged at medium severity."
        severity = "medium"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2026-04-27"

    strings:
        // Shell-style `$VAR` / `${VAR}`, GitHub Actions / Azure Pipelines
        // `${{ ... }}`, classic Azure Pipelines `$(var)`. The character class
        // gates on the byte after `$` so literal special-char passwords like
        // `password=$!a3#` (which the strict rule already catches) don't match.
        $tpl_dollar = /password\s*[:=]\s*\$[\{(A-Za-z_]/ nocase
        // Jinja2 / Helm / Liquid `{{ ... }}`
        $tpl_brace = /password\s*[:=]\s*\{\{/ nocase

    condition:
        any of them
}

rule secrets_generic_passwords_loose {
    meta:
        description = "Permissive password pattern — high false-positive rate on template expressions; info-only signal"
        severity = "info"
        category = "secrets_detection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2026-04-27"

    strings:
        // Original `$pass3_special` from `secrets_generic_passwords`: any-length
        // unquoted password value containing a special character. Fires on
        // template expressions (`PASSWORD: ${{ ... }}`) so it lives here at
        // info severity rather than in the strict rule.
        $pass3_special = /password\s*[:=]\s*[^\s]*[^A-Za-z0-9\s][^\s]*/ nocase

    condition:
        any of them
}

rule secrets_encryption_keys {
    meta:
        description = "Detects encryption keys and certificates"
        severity = "critical"
        category = "secrets_detection"
        mitre_attack = "T1552.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // AES keys (hex encoded)
        $aes256 = /aes[_-]?key['"\s]*[:=]['"\s]*[a-fA-F0-9]{64}/ nocase
        $aes128 = /aes[_-]?key['"\s]*[:=]['"\s]*[a-fA-F0-9]{32}/ nocase

        // Base64 encoded keys
        $base64_key = /encryption[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{32,}==?/ nocase

        // PGP Private Key
        $pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

        // Certificate Private Key
        $cert = "-----BEGIN CERTIFICATE-----"

    condition:
        any of them
}

rule secrets_ssh_config {
    meta:
        description = "Detects SSH configuration with sensitive info"
        severity = "high"
        category = "secrets_detection"
        mitre_attack = "T1552.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $host = "Host "
        $ssh_host = "IdentityFile"
        $ssh_pass = "Password"

        $identity = "IdentityFile"
        $ssh_key = ".ssh"

    condition:
        $host and $ssh_host or
        $host and $ssh_pass or
        $identity and $ssh_key
}

// Broad sk- secret-key token detection.
// Catches API secret keys from services (Mistral, Cohere, Pinecone, etc.)
// that use the sk- prefix with lengths outside the OpenAI-specific rule
// (exactly 48 chars) and the Anthropic-specific rule (sk-ant- + 95 chars).
rule secrets_sk_api_token {
    meta:
        description = "Detects generic sk- prefixed API secret key tokens (20+ alphanumeric chars)"
        severity     = "high"
        category     = "secrets_detection"
        mitre_attack = "T1552.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // sk- prefix with 20–47 alphanumeric chars (shorter than OpenAI's 48)
        // Covers Mistral, Cohere, Pinecone, and other services using sk- prefix.
        $sk_short = /\bsk-[A-Za-z0-9]{20,47}\b/

        // sk- prefix with 49–94 chars (longer than OpenAI 48, shorter than Anthropic 95)
        $sk_mid   = /\bsk-[A-Za-z0-9_\-]{49,94}\b/

    condition:
        any of them
}
