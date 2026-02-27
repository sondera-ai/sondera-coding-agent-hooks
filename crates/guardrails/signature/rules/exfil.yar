/*
   Data Exfiltration Detection Rules

   Description: Detects attempts to exfiltrate sensitive data through various channels
   Author: Sondera Security Team
   Date: 2025-11-13
   References:
     - MITRE ATT&CK T1041: Exfiltration Over C2 Channel
     - MITRE ATT&CK T1567: Exfiltration Over Web Service

   Usage: These rules detect attempts to extract and transmit sensitive data including:
     - Sensitive file access patterns
     - External data transmission commands
     - Paste site URLs
     - Encoding for exfiltration
     - API keys and credentials in transit
*/

rule data_exfiltration_sensitive_files {
    meta:
        description = "Detects access to sensitive credential and configuration files"
        severity = "critical"
        category = "credential_access"
        mitre_attack = "T1552.001"

    strings:
        // SSH keys
        $ssh1 = "/.ssh/id_rsa"
        $ssh2 = "/.ssh/id_ed25519"
        $ssh3 = "/.ssh/id_ecdsa"
        $ssh4 = "/.ssh/known_hosts"
        $ssh5 = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh6 = "-----BEGIN OPENSSH PRIVATE KEY-----"

        // Environment files
        $env1 = ".env"
        $env2 = ".env.local"
        $env3 = ".env.production"
        $env4 = ".env.development"

        // Certificate files
        $cert1 = ".pem"
        $cert2 = ".key"
        $cert3 = ".crt"
        $cert4 = ".pfx"
        $cert5 = ".p12"

        // Database credentials
        $db1 = ".my.cnf"
        $db2 = ".pgpass"
        $db3 = "database.yml"

    condition:
        any of them
}

rule data_exfiltration_cloud_credentials {
    meta:
        description = "Detects access to sensitive cloud credentials"
        severity = "critical"
        category = "credential_access"
        mitre_attack = "T1552.001"

    strings:
        // AWS credentials
        $aws1 = "/.aws/credentials"
        $aws2 = "aws_access_key_id"
        $aws3 = "aws_secret_access_key"

        // GCP credentials
        $gcp1 = "/.config/gcloud/application_default_credentials.json"
        $gcp2 = "/.config/gcloud/credentials.db"
        // GOOGLE_APPLICATION_CREDENTIALS
        $gcp3 = "service-account.json"

        // Azure credentials
        $azure1 = "/.azure/accessTokens.json"
        $azure2 = "/.azure/msal_token_cache.json"

        // OCI credentials
        $oracle1 = "/.oci/oci_api_key.pem"
        $oracle2 = "/.oci/oci_api_key_public.pem"
        $oracle3 = "/.oci/sessions/"

        // Vercel AI credentials
        $vercel1 = "/.local/share/vercel/token"

    condition:
        any of them
}

rule data_exfiltration_cloud_configs {
    meta:
        description = "Detects access to sensitive cloud configs"
        severity = "critical"
        category = "credential_access"
        mitre_attack = "T1552.001"

    strings:
        // Cloud provider configs
        $aws1 = "/.aws/config"
        $gcp1 = "/.config/gcloud/"
        $gcp2 = "/.config/gcloud/configurations/"
        $azure1 = "/.azure/"
        $azure2 = "/.azure/azureProfile.json"
        $azure3 = "/.azure/clouds.config"
        $oracle1 = "/.oci/config"
        $oracle2 = "/.oci/oci_cli_rc"
        $vercel1 = "/.config/vercel/"
        $vercel2 = "/.vercel/"

        // kubernetes configs
        $k8s1 = "/.kube/config"

    condition:
        any of them
}

rule data_exfiltration_paste_sites {
    meta:
        description = "Detects attempts to send data to paste/pastebin services"
        severity = "high"
        category = "exfiltration"
        mitre_attack = "T1567.001"

    strings:
        // Popular paste sites
        $paste1 = "pastebin.com"
        $paste2 = "paste.ee"
        $paste3 = "hastebin.com"
        $paste4 = "ghostbin.com"
        $paste5 = "dpaste.com"
        $paste6 = "paste.ubuntu.com"
        $paste7 = "gist.github.com"
        $paste8 = "justpaste.it"
        $paste9 = "paste2.org"
        $paste10 = "privatebin.net"
        $paste11 = "rentry.co"
        $paste12 = "controlc.com"

        // Actions with paste sites
        $action1 = /send\s+(to|data\s+to)\s+(pastebin|paste\.ee|hastebin)/i
        $action2 = /post\s+(to|data\s+to)\s+(pastebin|paste\.ee|hastebin)/i
        $action3 = /upload\s+(to|data\s+to)\s+(pastebin|paste\.ee|hastebin)/i

    condition:
        any of ($paste*) or any of ($action*)
}

rule data_exfiltration_external_domains {
    meta:
        description = "Detects suspicious external domain references for data exfiltration"
        severity = "high"
        category = "exfiltration"
        mitre_attack = "T1567.002"

    strings:
        // File sharing services
        $share1 = "dropbox.com"
        $share2 = "drive.google.com"
        $share3 = "onedrive.live.com"
        $share4 = "mega.nz"
        $share5 = "wetransfer.com"
        $share6 = "sendspace.com"
        $share7 = "mediafire.com"

        // Webhook services (often abused)
        $webhook1 = "webhook.site"
        $webhook2 = "requestbin.com"
        $webhook3 = "pipedream.com"
        $webhook4 = "zapier.com/hooks"

        // Discord webhooks (commonly abused)
        $discord = "discord.com/api/webhooks/"

        // ngrok/tunneling (suspicious in agent context)
        $tunnel1 = "ngrok.io"
        $tunnel2 = "localtunnel.me"
        $tunnel3 = "serveo.net"

        // Actions with external domains
        $send1 = /send\s+(data\s+)?to\s+https?:\/\/[^\s]+/i
        $post1 = /POST\s+https?:\/\/[^\s]+/i
        $curl1 = /curl\s+-X\s+POST\s+https?:\/\/[^\s]+/i

    condition:
        any of them
}

rule data_exfiltration_encoding_patterns {
    meta:
        description = "Detects encoding patterns commonly used for data exfiltration"
        severity = "medium"
        category = "defense_evasion"
        mitre_attack = "T1027"

    strings:
        // Base64 with exfiltration context
        $b64_1 = /base64\s+(encode|encoding)/i
        $b64_2 = /btoa\(/  // JavaScript base64 encode
        $b64_3 = /\.encode\('base64'\)/

        // Hex encoding
        $hex_1 = /hex\s+(encode|encoding)/i
        $hex_2 = /to_hex\(/
        $hex_3 = /\.hexdigest\(/

        // URL encoding for data
        $url_1 = /url\s+(encode|encoding)/i
        $url_2 = /encodeURIComponent\(/
        $url_3 = /urllib\.parse\.quote/

        // Compression before sending (common exfiltration pattern)
        $compress_1 = /gzip\s+/
        $compress_2 = /compress\s+(data|file)/i
        $compress_3 = /zip\s+(and\s+)?(send|upload|post)/i

    condition:
        any of them
}

rule data_exfiltration_api_keys_in_transit {
    meta:
        description = "Detects API keys in exfiltration context (combined with send/upload)"
        severity = "critical"
        category = "exfiltration"
        mitre_attack = "T1552.001"

    strings:
        // Exfiltration context keywords
        $exfil1 = /send|upload|post|transmit/i
        $exfil2 = /curl|wget|fetch/i

        // Generic patterns (require exfiltration context)
        $key_pattern = /[aA][pP][iI]_?[kK][eE][yY]|[sS][eE][cC][rR][eE][tT]/

    condition:
        (any of ($exfil*)) and $key_pattern
}

rule data_exfiltration_network_commands {
    meta:
        description = "Detects network commands commonly used for data exfiltration"
        severity = "high"
        category = "exfiltration"
        mitre_attack = "T1041"

    strings:
        // curl patterns
        $curl1 = /curl\s+-[A-Za-z]*d\s+/  // -d for data
        $curl2 = /curl\s+--data\s+/
        $curl3 = /curl\s+-[A-Za-z]*F\s+/  // -F for form upload
        $curl4 = /curl\s+--form\s+/
        $curl5 = /curl\s+-T\s+/  // -T for upload

        // wget patterns
        $wget1 = /wget\s+--post-data/
        $wget2 = /wget\s+--post-file/

        // HTTP methods with data
        $http1 = /POST\s+.*\s+HTTP\/[12]\.[01]/
        $http2 = /PUT\s+.*\s+HTTP\/[12]\.[01]/

        // Python requests
        $py1 = /requests\.post\(/
        $py2 = /requests\.put\(/
        $py3 = /urllib\.request\.urlopen\(/

        // JavaScript fetch/axios
        $js1 = /fetch\(.*method:\s*['"]POST['"]/
        $js2 = /axios\.post\(/

        // Netcat data transmission
        $nc1 = /nc\s+.*\s+-[A-Za-z]*w/
        $nc2 = /netcat\s+.*>/

    condition:
        any of them
}

rule data_exfiltration_file_read_with_send {
    meta:
        description = "Detects patterns of reading files and sending data"
        severity = "critical"
        category = "exfiltration"
        mitre_attack = "T1005 + T1041"

    strings:
        // Read file + send patterns
        $pattern1 = /cat\s+[\w\/.]+\s*\|\s*(curl|wget)/
        $pattern2 = /cat\s+[\w\/.]+\s*>\s*\/dev\/tcp/
        $pattern3 = /(read|open)\(['"][\w\/.]+['"].*\.(send|post|upload)/

        // Exfiltration commands
        $exfil1 = /exfiltrate\s+(data|file)/i
        $exfil2 = /send\s+(file|data)\s+to\s+http/i
        $exfil3 = /upload\s+(file|data)\s+to\s+http/i
        $exfil4 = /transmit\s+(file|data)/i

        // Copy to external location
        $copy1 = /cp\s+[\w\/.]+\s+http/
        $copy2 = /scp\s+[\w\/.]+\s+[\w@\.\-]+:/

    condition:
        any of them
}

rule data_exfiltration_dns_tunneling {
    meta:
        description = "Detects potential DNS tunneling for data exfiltration"
        severity = "high"
        category = "exfiltration"
        mitre_attack = "T1048.003"

    strings:
        // DNS tunneling tools
        $tool1 = "dnscat"
        $tool2 = "iodine"
        $tool3 = "dns2tcp"

        // Suspicious DNS query patterns
        $dns1 = /nslookup\s+[a-f0-9]{32,}/
        $dns2 = /dig\s+[a-f0-9]{32,}/
        $dns3 = /host\s+[a-f0-9]{32,}/

        // Long subdomain labels (common in DNS tunneling)
        $long_label = /[a-z0-9]{50,}\.[a-z0-9]+\.[a-z]{2,}/

    condition:
        any of them
}

rule data_exfiltration_steganography {
    meta:
        description = "Detects potential steganography techniques for data hiding"
        severity = "medium"
        category = "defense_evasion"
        mitre_attack = "T1027.003"

    strings:
        // Steganography tools
        $tool1 = "steghide"
        $tool2 = "outguess"
        $tool3 = "stegsnow"

        // Commands with steganography context
        $cmd1 = /embed\s+(data|message)\s+in\s+(image|audio|video)/i
        $cmd2 = /hide\s+(data|message)\s+in\s+(image|audio|video)/i
        $cmd3 = /encode\s+(data|message)\s+into\s+(image|audio|video)/i

        // LSB (Least Significant Bit) references
        $lsb = "LSB embedding" nocase

    condition:
        any of them
}

rule data_exfiltration_memory_dump {
    meta:
        description = "Detects attempts to dump memory or process information"
        severity = "high"
        category = "credential_access"
        mitre_attack = "T1003"

    strings:
        // Memory dump commands
        $dump1 = /dump\s+(memory|process|credentials)/i
        $dump2 = "memdump"
        $dump3 = "procdump"

        // Linux memory access
        $linux1 = "/proc/self/mem"
        $linux2 = "/proc/self/maps"
        $linux3 = "gcore"

        // Environment variable dump
        $env_dump1 = "env | grep"
        $env_dump2 = "printenv"
        $env_dump3 = "export -p"

    condition:
        any of them
}
