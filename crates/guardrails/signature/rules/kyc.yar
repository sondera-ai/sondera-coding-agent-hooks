/*
   KYC / Personal Data Detection Rules

   Description: Detects KYC (Know-Your-Customer) personal data under the
   `kyc_pii` and `kyc_email` categories. These rules are precision-first:
   false-negatives are preferred over false-positives.
   Author: Sondera Security Team
   References:
     - MITRE ATT&CK T1589: Gather Victim Identity Information

   Two rules, split by signal strength so policy and metrics can treat them
   separately:
     - kyc_pii   — structured IDs (SG NRIC) and label-gated name/DOB/address/
       phone/passport/SSN. High precision; each string fires on its own.
     - kyc_email — bare email addresses, a weaker identity signal that needs its
       own allowlist machinery: scp/ssh git remotes, machine/service-account
       domains, and operational noreply senders are all email-shaped but are not
       customer PII. Carried as a distinct `kyc_email` category so a future
       policy can gate email egress differently from structured IDs.

   Scope: each rule scans one event payload independently. These signatures do not
   correlate a file read in one event with a later network action.

   Precision model:
     - $sg_nric fires alone — distinctive enough to stand on its own.
     - The labeled patterns are field-gated: a label (name/dob/address/phone/
       passport/ssn) within a short window of the value. The value portion stays
       case-sensitive (uppercase IDs, Title-Case names) — that is the precision
       gate. YARA-X supports only the post-slash `/i` and `/s` modifiers, with no
       scoped `(?i:...)`, so a whole-pattern `/i` would also fold the value's
       case and over-match (e.g. `name: see above`). Patterns whose value is
       digits-only (ssn/phone/dob) therefore use `/i`; the rest spell the
       keyword's letters as case classes so only the label is case-insensitive.
     - Free-text names/addresses with no field label are the accepted gap.
     - Region IDs are per-locale (SG NRIC here); add more as needed.
     - The email branch's count-subtraction precision model is documented on
       kyc_email below.
*/

rule kyc_pii {
    meta:
        description = "KYC personal data — structured IDs (high precision) + labeled name/DOB/address/phone/passport"
        severity = "medium"
        category = "kyc_pii"
        mitre_attack = "T1589"

    strings:
        $sg_nric = /\b[STFG]\d{7}[A-Z]\b/                      // SG NRIC (region-specific)

        // Label-gated. Digit-only value tails can use `/i` (case is irrelevant
        // to digits/punctuation).
        $ssn_kw   = /(ssn|social security)[^\n]{0,20}\b\d{3}-\d{2}-\d{4}\b/i
        // `\b` on BOTH sides of the label: a leading-only boundary still
        // matches the `tel` prefix of `telemetry`; the trailing `\b` rejects
        // that, and the leading one rejects suffixes like `intel` / `hotel`.
        $phone_kw = /\b(phone|mobile|tel|contact)\b[^\n]{0,15}\+?\d[\d ().\-]{6,}\d/i
        // DOB in the three common civil orderings: DMY, US MDY, and ISO-8601
        // YMD. Each field is range-checked (day 1-31, month 1-12) so 31/31 is
        // rejected; an ambiguous DD/MM vs MM/DD resolves to DMY (listed first).
        // `\b` bounds the label so `born` doesn't fire inside `airborne`/`reborn`.
        $dob_kw   = /\b(dob|date of birth|born)\b[^\n]{0,15}\b((0?[1-9]|[12]\d|3[01])[\/.\-](0?[1-9]|1[0-2])[\/.\-](19|20)\d\d|(0?[1-9]|1[0-2])[\/.\-](0?[1-9]|[12]\d|3[01])[\/.\-](19|20)\d\d|(19|20)\d\d[\/.\-](0?[1-9]|1[0-2])[\/.\-](0?[1-9]|[12]\d|3[01]))\b/i

        // Label-gated with a CASE-SENSITIVE value tail (uppercase IDs /
        // Title-Case names). The label's letters are case classes so the label
        // matches case-insensitively while the value's case stays significant.
        $passport_kw = /([Pp][Aa][Ss][Ss][Pp][Oo][Rr][Tt]|[Kk][Yy][Cc]|[Nn][Aa][Tt][Ii][Oo][Nn][Aa][Ll] [Ii][Dd]|[Nn][Rr][Ii][Cc])[^\n]{0,20}\b[A-Z0-9][A-Z0-9-]{5,11}\b/
        $addr_kw     = /([Aa][Dd][Dd][Rr][Ee][Ss][Ss]|[Rr][Ee][Ss][Ii][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Hh][Oo][Mm][Ee] [Aa][Dd][Dd][Rr][Ee][Ss][Ss])\s*[:=][^\n]{0,60}\b\d{1,5}\s+[A-Z][a-z]+/
        $name_kw     = /([Nn][Aa][Mm][Ee]|[Cc][Uu][Ss][Tt][Oo][Mm][Ee][Rr]|[Aa][Cc][Cc][Oo][Uu][Nn][Tt] [Hh][Oo][Ll][Dd][Ee][Rr])\s*[:=]\s*[A-Z][a-z]+ [A-Z][a-z]+/

    condition:
        // Every structured / label-gated string fires on its own.
        any of them
}

rule kyc_email {
    meta:
        description = "Email address (potential KYC/PII) — excludes scp/ssh git remotes, machine/service-account domains, and operational noreply senders"
        severity = "medium"
        category = "kyc_email"
        mitre_attack = "T1589"

    strings:
        // $email is distinctive, but several email-SHAPED tokens are not
        // customer PII. YARA-X has no look-ahead/behind, so we can't write
        // `email (?!:path)`. Instead each exclusion below matches at the SAME
        // SITES as $email, and the condition fires only when at least one
        // email-shaped token is NOT covered by any exclusion:
        // #email > #scp_url + #svc_email + #noreply. Counting (not `... and not
        // $x`) is load-bearing: an `and not` would let one injected
        // remote/service/noreply token silence a real customer email in the same
        // blob.
        //
        // START ANCHOR — `(^|[^<local>])`, NOT `\b`. yara-x counts OVERLAPPING
        // regex matches, and `\b` sits at every internal local-part boundary
        // created by a non-word char (`.`, `-`, `+`, `%`). So `\b[local]+@dom`
        // matches `no-reply@x` at offsets `no-reply@`, `-reply@`, AND `reply@` —
        // #email == 3 for ONE address. A domain-keyed exclusion ($scp_url,
        // $svc_email) inflates in lockstep (each suffix keeps the same domain),
        // but a LOCAL-part-keyed exclusion ($noreply) only matches the offset
        // where the keyword is intact (1), so #email > #noreply spuriously fired.
        // Anchoring the start to data-start-or-a-non-local char makes every
        // address match EXACTLY once, so all four counts are 1-per-address and
        // the subtraction is exact.
        $email   = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/

        // scp/ssh git remotes (`git@github.com:org/repo`) are email-shaped: an
        // email shape followed by `:`/`/` + a path char. Same start anchor and
        // `[local]+@` prefix as $email → a strict SUBSET of its sites, so
        // #scp_url <= #email always.
        $scp_url = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[:\/][A-Za-z0-9._~-]/

        // Machine/service-account domains (GCP service accounts, GitHub noreply,
        // AWS) — infrastructure identity, not customer PII. Same start anchor and
        // `[local]+@` prefix as $email → matches at the SAME sites, a strict
        // SUBSET like $scp_url. The optional `(?:[A-Za-z0-9.-]+\.)?` group (its
        // class includes `.`) lets the suffix match whether the domain is bare
        // (`@noreply.github.com`) or carries any multi-label prefix
        // (`@<proj>.iam.gserviceaccount.com`,
        // `@bounce.email.us-east-1.amazonaws.com`). The list collapses under a few
        // parent suffixes: `gserviceaccount.com` covers every GCP SA and
        // `noreply.github.com` also covers `users.noreply.github.com`. NOTE:
        // `example.{com,org,net}` is deliberately NOT here — RFC-2606 reserved
        // domains are the codebase's stand-in for real customer emails (see the
        // kyc_email tests), so carving them out would silence genuine PII. yara-x
        // caps an alternation at 255 branches; if this list ever nears that,
        // split into $svc_email0/1/... and sum their counts in the condition.
        //
        $svc_email = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9.-]+\.)?(gserviceaccount\.com|noreply\.github\.com|amazonaws\.com)\b/

        // Operational noreply / bounce senders (`alerting-noreply@google.com`,
        // `mailer-daemon@…`, `postmaster@…`) — machine senders identified by the
        // LOCAL part, not the domain, so unlike $svc_email this keys on the
        // mailbox. The `[local]*<keyword>[local]*@<domain>` shape, with the same
        // start anchor as $email, matches each such address exactly once.
        // `no-?reply`/`do-?not-?reply` cover the hyphenated and run-together
        // spellings; the leading/trailing `[local]*` catch prefixes/suffixes like
        // `alerting-noreply` and `noreply+tag`.
        $noreply = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(no-?reply|do-?not-?reply|mailer-daemon|postmaster)[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i

    condition:
        // Fire only when an email-shaped token exists that is NOT an scp/ssh
        // remote, NOT a known service-account address, and NOT a noreply sender.
        // Each exclusion is a strict subset of $email, so subtracting their
        // counts yields the number of "real" customer-looking emails. A
        // repos.json full of `git@github.com:org/repo` has #email == #scp_url → no
        // match; a memory diff full of `…@…gserviceaccount.com` SAs has
        // #email == #svc_email → no match; an alert blob whose only address is
        // `alerting-noreply@google.com` has #email == #noreply → no match; one
        // real customer email tips #email ahead → match.
        //
        // Precision-first edge case: a token that matches two exclusions at once
        // (e.g. `no-reply@noreply.github.com` is both $svc_email and $noreply, or
        // `git@gserviceaccount.com:path` is both $scp_url and $svc_email) is
        // counted twice, over-subtracting by one — a lone such token could mask
        // one real customer email. Acceptable under this rule's stated
        // false-negative-tolerant stance (see header); noted so it doesn't read
        // as a bug.
        #email > #scp_url + #svc_email + #noreply
}
