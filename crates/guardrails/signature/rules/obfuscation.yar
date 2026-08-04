/*
 * Obfuscation Detection Rules
 *
 * Detects obfuscation and encoding techniques in AI agent interactions including:
 * - Base64 encoding
 * - Hex encoding
 * - URL encoding
 * - Unicode obfuscation
 * - ROT13 and Caesar cipher
 * - HTML/XML entity encoding
 */

rule obfuscation_base64_encoded_commands {
    meta:
        description = "Detects base64 encoded shell commands and suspicious strings"
        severity = "high"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Base64 encoded common commands (partial matches)
        $b64_bash = "YmFzaA==" // "bash"
        $b64_sh = "c2g=" // "sh"
        $b64_curl = "Y3VybA==" // "curl"
        $b64_wget = "d2dldA==" // "wget"
        $b64_cat = "Y2F0" // "cat"
        $b64_rm = "cm0g" // "rm "
        $b64_chmod = "Y2htb2Q=" // "chmod"
        $b64_eval = "ZXZhbA==" // "eval"

        // Base64 encoded path traversal
        $b64_dotdot = "Li4v" // "../"
        $b64_etc = "L2V0Yy8=" // "/etc/"

        // Base64 encoded SQL injection
        $b64_drop = "RFJPUCBUQUJMRQ==" // "DROP TABLE"
        $b64_union = "VU5JT04gU0VMRUNU" // "UNION SELECT"

        // Long base64 strings (potential encoded payloads)
        $long_b64 = /[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        any of ($b64_*) or
        (2 of them) // Flag if multiple encodings present
}

rule obfuscation_hex_encoding {
    meta:
        description = "Detects hex encoded commands and strings"
        severity = "high"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Hex encoded commands
        $hex_bash = /\\x62\\x61\\x73\\x68/ // bash
        $hex_sh = /\\x73\\x68/ // sh
        $hex_curl = /\\x63\\x75\\x72\\x6c/ // curl
        $hex_eval = /\\x65\\x76\\x61\\x6c/ // eval

        // URL hex encoding
        $url_hex1 = /%2[eE]%2[eE]%2[fF]/ // ../
        $url_hex2 = /%5[bB]/ // [
        $url_hex3 = /%7[bB]/ // {

        // Hex string pattern (long sequences)
        $hex_long = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/

        // 0x prefix hex
        $hex_prefix = /0x[0-9a-fA-F]{2}([,\s]+0x[0-9a-fA-F]{2}){10,}/

    condition:
        any of them
}

rule obfuscation_unicode_homoglyphs {
    meta:
        description = "Detects Unicode homoglyph obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027.010"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Cyrillic lookalikes
        $cyrillic_a = "а" // Cyrillic 'a' looks like Latin 'a'
        $cyrillic_e = "е" // Cyrillic 'e'
        $cyrillic_i = "і" // Cyrillic 'i'
        $cyrillic_o = "о" // Cyrillic 'o'
        $cyrillic_p = "р" // Cyrillic 'p'

        // Greek lookalikes
        $greek_o = "ο" // Greek omicron
        $greek_a = "α" // Greek alpha

        // Mathematical alphanumeric
        $math_unicode_prefix = { F0 9D } // Bold/italic mathematical symbols

        // Combining diacritics (invisible)
        $combining = /(?:[\xCC-\xCD][\x80-\xBF]){2,}/ // Multiple combining marks

        // Zero-width characters
        $zero_width = /(\\xE2\\x80[\\x8B-\\x8D]|\\xEF\\xBB\\xBF)/ // Zero-width space, joiner, etc

    condition:
        any of them
}

rule obfuscation_html_entity_encoding {
    meta:
        description = "Detects HTML/XML entity encoding for obfuscation in commands/scripts"
        severity = "high"
        category = "obfuscation"
        mitre_attack = "T1027.010"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Encoded dangerous patterns (not prompt-specific)
        $entity_script = "&#115;&#99;&#114;&#105;&#112;&#116;" // "script"
        $entity_bash = "&#98;&#97;&#115;&#104;" // "bash"
        $entity_eval = "&#101;&#118;&#97;&#108;" // "eval"

        // Multiple HTML entities in sequence
        $entity_chain = /&#[0-9]{2,3};(&#[0-9]{2,3};){7,}/

        // Unicode HTML entities (long sequences)
        $unicode_entity = /&#x[0-9a-fA-F]{2,4};(&#x[0-9a-fA-F]{2,4};){7,}/

        // Mixed encoding
        $mixed = "&#"
        $mixed2 = "\\x"
        $mixed3 = "%"

    condition:
        $entity_script or $entity_bash or $entity_eval or
        $entity_chain or
        $unicode_entity or
        $mixed and $mixed2 and $mixed3
}

rule obfuscation_url_encoding {
    meta:
        description = "Detects excessive URL encoding for obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Double URL encoding
        $double_encode = /%25[0-9a-fA-F]{2}/

        // URL encoded commands
        $url_bash = "%62%61%73%68" // bash
        $url_curl = "%63%75%72%6c" // curl
        $url_script = "%73%63%72%69%70%74" // script

        // Excessive URL encoding
        $url_chain = /(%[0-9a-fA-F]{2}){10,}/

    condition:
        any of them
}

rule obfuscation_character_substitution {
    meta:
        description = "Detects character substitution obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Leetspeak
        $leet1 = /p@ssw0rd/i
        $leet2 = /h4ck/i
        $leet3 = /3v4l/i
        $leet4 = /4dm1n/i

        // Reversed strings (common technique)
        $reversed1 = "hsab" // "bash" reversed
        $reversed2 = "tpircs" // "script" reversed
        $reversed3 = "lruc" // "curl" reversed

        // Character insertion (require at least one space to avoid matching plain words)
        $insert = /b\s+a\s+s\s+h/ // spaces between chars
        $insert2 = /c\s+u\s+r\s+l/

    condition:
        any of them
}

rule obfuscation_concatenation {
    meta:
        description = "Detects string concatenation for obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Bash concatenation
        $concat1 = /["'][a-z]+["']\+["'][a-z]+["']/
        $concat2 = /["'][a-z]+["']\.["'][a-z]+["']/

        // Variable concatenation
        $var_concat = /\$\{[a-zA-Z_][a-zA-Z0-9_]*\}\$\{[a-zA-Z_][a-zA-Z0-9_]*\}/

        // JavaScript/Python concatenation
        $js_concat = /['"][a-z]+['"]\ *\+\ *['"][a-z]+['"]/

    condition:
        2 of them // Multiple concatenations suggest obfuscation
}

rule obfuscation_rot13_encoding {
    meta:
        description = "Detects ROT13 or Caesar cipher encoding"
        severity = "low"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // ROT13 encoded common words
        $rot13_bash = "onfpu" // "bash" in ROT13
        $rot13_curl = "phey" // "curl" in ROT13
        $rot13_eval = "riny" // "eval" in ROT13
        $rot13_exec = "rkrp" // "exec" in ROT13
        $rot13_python = "clguba" // "python" in ROT13
        $rot13_script = "fpevcg" // "script" in ROT13
        $rot13_system = "flfgrz" // "system" in ROT13

    condition:
        2 of them
}

rule obfuscation_json_escape_sequences {
    meta:
        description = "Detects excessive JSON escape sequences for obfuscation"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Unicode escape sequences in JSON
        $unicode_escape = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}/

        // Mixed escape sequences
        $mixed_escape = /\\[nrtbf\\\/](\\[nrtbf\\\/]){10,}/

        // Escaped quotes pattern (raised from 5 to 15 to avoid false positives on
        // JSON config files with many quoted arguments in shell commands)
        $quote_escape = /\\["'](\s*\\["']){15,}/

    condition:
        any of them
}

rule obfuscation_whitespace_manipulation {
    meta:
        description = "Detects whitespace-based obfuscation"
        severity = "low"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Excessive tabs
        $tabs = /\t{20,}/

        // Non-breaking spaces
        $nbsp = /\u00A0{5,}/

        // Other Unicode spaces
        $unicode_space = /(\\xE2\\x80[\\x80-\\x8A]){5,}/

    condition:
        any of them
}

rule obfuscation_comment_hiding {
    meta:
        description = "Detects code hidden in comments"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Hash comments hiding a call to eval(...) / exec(...). The
        // function-call form keeps ordinary English ("# evaluate the
        // config", "# execution context", "# removed via --disallowedTools")
        // from matching while still catching `# eval(atob("..."))` payloads.
        $bash_comment = /#.*\beval\s*\(/
        $bash_comment2 = /#.*\bexec\s*\(/
        // Hash comment hiding a curl | sh / curl | bash pipeline.
        $bash_comment3 = /#.*\bcurl\b.*\|\s*(sh|bash)\b/

        // C-style comment containing an eval(...) call on the same line.
        $multiline = /\/\*.*\beval\s*\(.*\*\//

        // HTML comment hiding an actual <script> tag (not just the word).
        $html_comment = /<!--.*<script\b.*-->/

    condition:
        any of them
}

rule obfuscation_polyglot_file {
    meta:
        description = "Detects polyglot file indicators (multiple file types)"
        severity = "high"
        category = "obfuscation"
        mitre_attack = "T1027.003"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // PDF + executable
        $pdf_exec = "%PDF"
        $pdf_exec2 = "MZ"

        // Image + script
        $img_script = /\xFF\xD8\xFF/
        $img_script2 = "<script>" // JPEG + HTML

        // ZIP + script
        $zip_script = "PK\x03\x04"
        $zip_script2 = "eval("

    condition:
        $pdf_exec and $pdf_exec2 or
        $img_script and $img_script2 or
        $zip_script and $zip_script2
}

rule obfuscation_variable_naming {
    meta:
        description = "Detects obfuscated variable naming patterns"
        severity = "low"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Single letter variables in sequence
        $single_vars = /\$[a-z]\s*=.*\$[a-z]\s*=.*\$[a-z]\s*=/

        // Underscore-only variables
        $underscores = /\$_{2,}/

        // Numeric-only variables
        $numbers = /\$[0-9]{2,}/

        // Mixed gibberish variables
        $gibberish = /\$[a-zA-Z0-9_]{20,}/

    condition:
        2 of them
}

rule obfuscation_encoding_function_calls {
    meta:
        description = "Detects encoding/decoding function calls used for obfuscation"
        severity = "high"
        category = "obfuscation"
        mitre_attack = "T1027"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Base64 decode
        $b64_decode = /base64\s*-d/
        $b64_decode2 = "atob("
        $b64_decode3 = "base64_decode("

        // URL decode
        $url_decode = "urldecode("
        $url_decode2 = "decodeURIComponent("

        // Hex decode
        $hex_decode = "unhexlify("
        $hex_decode2 = "hex2bin("

        // Decode-to-execute pipelines — always suspicious
        $pipe_exec = /base64\s*-d\s*\|\s*(sh|bash|python|perl)/
        // Sequential: decode(...); eval(...)
        $decode_then_eval = /(atob|base64_decode|unhexlify|hex2bin)\s*\([^)]*\)\s*[);,]\s*(eval|exec)\s*\(/
        // Nested: eval(atob(...)), exec(base64_decode(...)), etc.
        $eval_of_decode = /(eval|exec)\s*\(\s*(atob|base64_decode|unhexlify|hex2bin|urldecode)\s*\(/

        // Python-specific: exec(base64.b64decode(...)) — not caught by $eval_of_decode
        // because Python uses the dotted module form `base64.b64decode`, not `base64_decode`.
        $py_b64exec = /(eval|exec)\s*\(\s*base64\.b64decode\s*\(/

        // Python-specific: exec(compile(<decode>(...))) — dynamic compilation of a decoded payload.
        // Plain exec(compile(source_var, ...)) without a decode step is not flagged.
        $py_compile = /exec\s*\(\s*compile\s*\(\s*(base64\.[a-z0-9_]+\s*\(|unhexlify\s*\(|hex2bin\s*\(|b64decode\s*\()/

        // Node.js: eval(Buffer.from(<data>, 'base64').toString())
        $js_buf_b64 = /eval\s*\(\s*Buffer\.from\s*\([^)]*'base64'\)/

    condition:
        // Direct decode-to-execute patterns are always suspicious.
        // Multiple decode functions together suggest obfuscation even without
        // an explicit exec (the decoded payload may self-execute).
        any of ($pipe_exec, $decode_then_eval, $eval_of_decode,
                $py_b64exec, $py_compile, $js_buf_b64) or
        (2 of ($b64_decode*) or 2 of ($url_decode*) or 2 of ($hex_decode*))
}
