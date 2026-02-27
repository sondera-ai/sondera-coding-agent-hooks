// ═══════════════════════════════════════════════════════
// Sondera – Supply Chain Security Policies
// ═══════════════════════════════════════════════════════
//
// Guards against software supply chain attacks that abuse
// package managers, dependency resolution, build systems,
// and artifact registries. AI coding agents are high-value
// vectors for supply chain compromise because they can
// silently install packages, modify manifests, and alter
// build configurations without human review.
//
// Unlike base.cedar (signature-based detection) and
// destructive.cedar (irreversible operations), these
// policies target the *software supply chain attack
// surface*: untrusted sources, registry manipulation,
// install script abuse, artifact publishing, and build
// system tampering.
//
// Organized by attack surface:
//
//   §1  Untrusted Package Sources & Registry Manipulation
//   §2  Suspicious Package Installation Patterns
//   §3  Install Script Bypass & Abuse
//   §4  Package Publishing Guards
//   §5  Lockfile & Manifest Integrity
//   §6  Build Configuration Tampering
//   §7  Dependency Pinning & Version Manipulation
//   §8  Compound Guards — Supply Chain + Sensitivity

// ═══════════════════════════════════════════════════════
// §1  Untrusted Package Sources & Registry Manipulation
// ═══════════════════════════════════════════════════════
//
// Block commands and file modifications that redirect
// package resolution to untrusted registries. Attackers
// use registry manipulation to serve malicious packages
// that shadow legitimate ones (dependency confusion).

@id("sc-forbid-npm-registry-override")
@description("Supply chain: block npm commands that override the default registry — prevents dependency confusion via malicious registries.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm *--registry *" &&
    !(context.command like "*--registry *registry.npmjs.org*")
};

@id("sc-forbid-pip-index-override")
@description("Supply chain: block pip commands that override the package index — prevents installation from malicious PyPI mirrors.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pip install*--index-url *" ||
    context.command like "*pip install*--extra-index-url *" ||
    context.command like "*pip install*-i *"
};

@id("sc-forbid-yarn-registry-override")
@description("Supply chain: block yarn commands that override the registry — prevents dependency confusion.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*yarn *--registry *" &&
    !(context.command like "*--registry *registry.yarnpkg.com*" ||
      context.command like "*--registry *registry.npmjs.org*")
};

@id("sc-forbid-gem-source-override")
@description("Supply chain: block gem commands with custom sources — prevents installation from untrusted gem servers.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*gem install*--source *" ||
    context.command like "*gem sources --add *"
};

@id("sc-forbid-cargo-registry-override")
@description("Supply chain: block cargo commands that use alternate registries — prevents supply chain attacks via Rust crate mirrors.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*cargo install*--registry *" ||
    context.command like "*cargo publish*--registry *"
};

// ─── Registry config file guards ───

@id("sc-forbid-write-registry-config-npmrc")
@description("Supply chain: block writing .npmrc files that could redirect package resolution to malicious registries.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.npmrc" ||
    context.path like "*npmrc"
};

@id("sc-forbid-write-registry-config-pip")
@description("Supply chain: block writing pip.conf / pip.ini files that could redirect package resolution.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/pip.conf" ||
    context.path like "*/pip.ini" ||
    context.path like "*/.pip/*"
};

@id("sc-forbid-write-cargo-config")
@description("Supply chain: block writing Cargo config files that could redirect crate resolution to alternate registries.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.cargo/config" ||
    context.path like "*/.cargo/config.toml"
};

// ═══════════════════════════════════════════════════════
// §2  Suspicious Package Installation Patterns
// ═══════════════════════════════════════════════════════
//
// Block installation of packages from URLs, git repos,
// local tarballs, or other non-registry sources. These
// bypass the registry's integrity checks and can deliver
// arbitrary code.

@id("sc-forbid-pip-install-url")
@description("Supply chain: block pip install from URLs and git repos — bypasses PyPI integrity checks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pip install *http://*" ||
    context.command like "*pip install *https://*" ||
    context.command like "*pip install *git+*" ||
    context.command like "*pip install *svn+*"
};

@id("sc-forbid-npm-install-url")
@description("Supply chain: block npm install from URLs and git repos — bypasses registry integrity checks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm install *http://*" ||
    context.command like "*npm install *https://*" ||
    context.command like "*npm install *git+*" ||
    context.command like "*npm install *git://*" ||
    context.command like "*npm install *.tgz*" ||
    context.command like "*npm install *.tar.gz*"
};

@id("sc-forbid-pip-install-tarball")
@description("Supply chain: block pip install from local archives — may contain tampered packages.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*pip install *.tar.gz*" ||
     context.command like "*pip install *.whl*" ||
     context.command like "*pip install *.zip*") &&
    !(context.command like "*pip install *dist/*")
};

@id("sc-forbid-go-install-vanity")
@description("Supply chain: block go install from non-standard module paths — prevents typosquatting via vanity import paths.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*go install *" &&
    !(context.command like "*go install *github.com/*" ||
      context.command like "*go install *golang.org/*" ||
      context.command like "*go install *google.golang.org/*" ||
      context.command like "*go install *./...")
};

// ═══════════════════════════════════════════════════════
// §3  Install Script Bypass & Abuse
// ═══════════════════════════════════════════════════════
//
// Block commands that disable install script safety
// mechanisms or execute arbitrary setup code. Install
// scripts (postinstall, setup.py) are the primary
// execution vector in supply chain attacks.

@id("sc-forbid-npm-ignore-scripts-bypass")
@description("Supply chain: block npm commands that explicitly re-enable ignored scripts — prevents bypassing install script protections.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm *--ignore-scripts=false*" ||
    context.command like "*npm config set ignore-scripts false*"
};

@id("sc-forbid-pip-setup-exec")
@description("Supply chain: block pip install commands that execute setup.py directly — arbitrary code execution during install.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*python*setup.py install*" ||
    context.command like "*python*setup.py develop*" ||
    context.command like "*pip install -e *git+*"
};

@id("sc-forbid-pip-no-binary")
@description("Supply chain: block pip install --no-binary — forces source builds that execute setup.py, enabling arbitrary code execution.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pip install*--no-binary*"
};

@id("sc-forbid-gem-install-no-verify")
@description("Supply chain: block gem install commands that skip signature verification.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*gem install*--no-document*--trust-policy*" ||
    context.command like "*gem install*--force*"
};

// ═══════════════════════════════════════════════════════
// §4  Package Publishing Guards
// ═══════════════════════════════════════════════════════
//
// Block commands that publish packages to registries.
// An AI agent should never publish packages without
// explicit human authorization — accidental publishes
// can expose internal code or credentials.

@id("sc-forbid-npm-publish")
@description("Supply chain: block npm publish — agent should never publish packages to registries without human review.")
forbid (
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm publish*"
};

@id("sc-forbid-pip-publish")
@description("Supply chain: block Python package publishing (twine, flit, poetry publish) — prevents accidental or malicious package releases.")
forbid (
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*twine upload*" ||
    context.command like "*flit publish*" ||
    context.command like "*poetry publish*" ||
    context.command like "*python*-m build*&&*twine*"
};

@id("sc-forbid-cargo-publish")
@description("Supply chain: block cargo publish — prevents accidental crate publication.")
forbid (
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*cargo publish*" &&
    !(context.command like "*cargo publish*--dry-run*")
};

@id("sc-forbid-gem-push")
@description("Supply chain: block gem push — prevents accidental gem publication.")
forbid (
    principal is Agent,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*gem push*"
};

// ═══════════════════════════════════════════════════════
// §5  Lockfile & Manifest Integrity
// ═══════════════════════════════════════════════════════
//
// Guard dependency manifests from modifications that
// could introduce malicious or vulnerable packages.
// While destructive.cedar blocks lockfile deletion,
// these policies guard against subtle tampering of
// manifest files (package.json, pyproject.toml, etc.)
// when YARA signatures detect suspicious content.

@id("sc-forbid-manifest-write-with-obfuscation")
@description("Supply chain: block writing dependency manifests when obfuscation detected — prevents injection of obfuscated package references.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*package.json" ||
     context.path like "*pyproject.toml" ||
     context.path like "*Cargo.toml" ||
     context.path like "*Gemfile" ||
     context.path like "*go.mod" ||
     context.path like "*requirements*.txt" ||
     context.path like "*pom.xml" ||
     context.path like "*build.gradle*") &&
    context.signature.categories.contains("obfuscation")
};

@id("sc-forbid-manifest-write-with-exfiltration")
@description("Supply chain: block writing dependency manifests when exfiltration patterns detected — prevents install-time data exfiltration via package scripts.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*package.json" ||
     context.path like "*pyproject.toml" ||
     context.path like "*Cargo.toml" ||
     context.path like "*Gemfile" ||
     context.path like "*go.mod" ||
     context.path like "*requirements*.txt" ||
     context.path like "*pom.xml" ||
     context.path like "*build.gradle*") &&
    context.signature.categories.contains("exfiltration")
};

@id("sc-forbid-lockfile-write-with-signatures")
@description("Supply chain: block writing lockfiles when any YARA signature matches — lockfile modifications should be clean.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*package-lock.json" ||
     context.path like "*yarn.lock" ||
     context.path like "*pnpm-lock.yaml" ||
     context.path like "*bun.lockb" ||
     context.path like "*Cargo.lock" ||
     context.path like "*Gemfile.lock" ||
     context.path like "*poetry.lock" ||
     context.path like "*uv.lock" ||
     context.path like "*composer.lock" ||
     context.path like "*go.sum") &&
    context.signature.matches > 0
};

// ═══════════════════════════════════════════════════════
// §6  Build Configuration Tampering
// ═══════════════════════════════════════════════════════
//
// Guard build system configuration files from malicious
// modifications. Attackers inject pre/post-build scripts,
// modified compiler flags, or additional build steps that
// execute arbitrary code during the build process.

@id("sc-forbid-build-config-injection")
@description("Supply chain: block writing build configs with command injection patterns — prevents build-time code execution.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*Makefile" ||
     context.path like "*CMakeLists.txt" ||
     context.path like "*build.gradle*" ||
     context.path like "*pom.xml" ||
     context.path like "*webpack.config.*" ||
     context.path like "*rollup.config.*" ||
     context.path like "*vite.config.*" ||
     context.path like "*esbuild.*") &&
    context.signature.categories.contains("command_injection")
};

@id("sc-forbid-build-config-exfiltration")
@description("Supply chain: block writing build configs with exfiltration patterns — prevents build-time data theft.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*Makefile" ||
     context.path like "*CMakeLists.txt" ||
     context.path like "*build.gradle*" ||
     context.path like "*pom.xml" ||
     context.path like "*webpack.config.*" ||
     context.path like "*rollup.config.*" ||
     context.path like "*vite.config.*") &&
    context.signature.categories.contains("exfiltration")
};

@id("sc-forbid-ci-config-injection")
@description("Supply chain: block writing CI/CD configs with command injection — prevents pipeline compromise.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.github/workflows/*" ||
     context.path like "*.gitlab-ci.yml" ||
     context.path like "*Jenkinsfile" ||
     context.path like "*.circleci/config.yml" ||
     context.path like "*.travis.yml" ||
     context.path like "*cloudbuild.yaml" ||
     context.path like "*buildspec.yml") &&
    context.signature.categories.contains("command_injection")
};

@id("sc-forbid-ci-config-secrets")
@description("Supply chain: block writing CI/CD configs with secrets patterns — prevents credential embedding in pipelines.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.path like "*.github/workflows/*" ||
     context.path like "*.gitlab-ci.yml" ||
     context.path like "*Jenkinsfile" ||
     context.path like "*.circleci/config.yml" ||
     context.path like "*.travis.yml" ||
     context.path like "*cloudbuild.yaml" ||
     context.path like "*buildspec.yml") &&
    context.signature.categories.contains("secrets_detection")
};

// ═══════════════════════════════════════════════════════
// §7  Dependency Pinning & Version Manipulation
// ═══════════════════════════════════════════════════════
//
// Block commands that deliberately disable dependency
// verification or integrity checking mechanisms.

@id("sc-forbid-npm-audit-disable")
@description("Supply chain: block commands that disable npm audit — prevents suppressing vulnerability warnings.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*npm set audit false*" ||
    context.command like "*npm config set audit false*" ||
    context.command like "*npm install*--no-audit*--no-fund*--no-package-lock*"
};

@id("sc-forbid-pip-trusted-host")
@description("Supply chain: block pip --trusted-host — disables TLS verification for package downloads, enabling MITM attacks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pip install*--trusted-host *"
};

@id("sc-forbid-pip-disable-requires-hashes")
@description("Supply chain: block pip install commands that ignore hash checking — disables integrity verification.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pip install*--no-deps*--no-verify*" ||
    context.command like "*pip install*--require-hashes*" &&
    context.command like "*--no-deps*"
};

@id("sc-forbid-cargo-deny-bypass")
@description("Supply chain: block commands that skip cargo install verification — prevents bypassing dependency auditing.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*cargo install*--no-verify*"
};

// ═══════════════════════════════════════════════════════
// §8  Compound Guards — Supply Chain + Sensitivity
// ═══════════════════════════════════════════════════════
//
// Stricter controls when supply chain operations occur
// on trajectories carrying sensitive data. Installing
// packages on a trajectory that has accessed confidential
// code creates a risk of data leakage through install
// scripts or build hooks.

@id("sc-forbid-install-on-highly-confidential-trajectory")
@description("Supply chain+IFC: block all package installations when trajectory carries highly confidential data — install scripts could exfiltrate sensitive data.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    (context.command like "*npm install*" ||
     context.command like "*npm add*" ||
     context.command like "*yarn add*" ||
     context.command like "*pnpm add*" ||
     context.command like "*bun add*" ||
     context.command like "*pip install*" ||
     context.command like "*uv pip install*" ||
     context.command like "*uv add*" ||
     context.command like "*cargo install*" ||
     context.command like "*cargo add*" ||
     context.command like "*gem install*" ||
     context.command like "*go install*" ||
     context.command like "*go get*")
};

@id("sc-forbid-install-on-exfil-tainted-trajectory")
@description("Supply chain+IFC: block package installations on exfiltration-tainted trajectories — install scripts are an alternate exfiltration channel.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.taints.contains(Taint::"exfiltration") &&
    (context.command like "*npm install*" ||
     context.command like "*npm add*" ||
     context.command like "*yarn add*" ||
     context.command like "*pnpm add*" ||
     context.command like "*pip install*" ||
     context.command like "*uv pip install*" ||
     context.command like "*uv add*" ||
     context.command like "*cargo install*" ||
     context.command like "*cargo add*" ||
     context.command like "*gem install*" ||
     context.command like "*go install*" ||
     context.command like "*go get*")
};

@id("sc-forbid-manifest-write-on-confidential-trajectory")
@description("Supply chain+IFC: block dependency manifest changes on confidential trajectories when signatures detected — prevents trojanized dependency injection on sensitive projects.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    (context.label == Label::"Confidential" ||
     context.label == Label::"HighlyConfidential") &&
    context.signature.matches > 0 &&
    (context.path like "*package.json" ||
     context.path like "*pyproject.toml" ||
     context.path like "*Cargo.toml" ||
     context.path like "*Gemfile" ||
     context.path like "*go.mod" ||
     context.path like "*requirements*.txt")
};
