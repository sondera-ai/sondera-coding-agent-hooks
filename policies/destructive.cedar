// ═══════════════════════════════════════════════════════
// Sondera – Destructive Operation Governance Policies
// ═══════════════════════════════════════════════════════
//
// Guards against destructive shell commands, file operations,
// and infrastructure actions that can cause irreversible damage.
// Builds on the base policies in base.cedar.
//
// Strategy: targeted forbids for commands and patterns that
// destroy data, force-overwrite state, or bypass safety
// mechanisms. Each policy is scoped to the specific action
// type and uses command/path pattern matching via `like`.
//
// ─── Coverage ───────────────────────────────────────────
//
//   §1  Filesystem Destruction – rm, shred, wipe
//   §2  Git Destructive Operations – force push, hard reset
//   §3  Infrastructure Teardown – terraform, docker, k8s
//   §4  Database Destruction – DROP, TRUNCATE, DELETE
//   §5  Package & Dependency Destruction – rm lockfiles
//   §6  Recursive Permission & Ownership Changes
//   §7  Disk & Partition Operations
//   §8  Critical File Deletion Guards

// ═══════════════════════════════════════════════════════
// §1  Filesystem Destruction
// ═══════════════════════════════════════════════════════
//
// Block shell commands that recursively delete files,
// overwrite data, or wipe filesystems. These are nearly
// always irreversible and catastrophic in a dev environment.

@id("forbid-rm-rf")
@description("Block recursive force-delete commands (rm -rf) — prevents accidental or malicious filesystem wipe.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -rf *" ||
    context.command like "*rm -fr *" ||
    context.command like "*rm -Rf *"
};

@id("forbid-rm-recursive")
@description("Block recursive delete without force flag — still destructive, requires review.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -r /*" ||
    context.command like "*rm -r ~*"
};

@id("forbid-rm-root")
@description("Block any rm targeting root or home directories — catastrophic data loss.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm * /*" ||
    context.command like "*rm /*"
};

@id("forbid-shred")
@description("Block shred commands — secure deletion makes recovery impossible.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*shred *"
};

@id("forbid-wipe-dd")
@description("Block dd commands that write to block devices — can destroy entire disks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*dd *of=/dev/*"
};

@id("forbid-mkfs")
@description("Block filesystem creation commands — erases all data on the target device.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*mkfs*"
};

@id("forbid-dev-null-redirect")
@description("Block redirecting important files to /dev/null — silently destroys data.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*> /dev/null 2>&1 <*" ||
    context.command like "*cat /dev/null >*"
};

// ═══════════════════════════════════════════════════════
// §2  Git Destructive Operations
// ═══════════════════════════════════════════════════════
//
// Block git commands that rewrite history, discard work,
// or force-push to shared branches. These can cause
// permanent loss of commits and break collaborators.

@id("forbid-git-force-push")
@description("Block git force push — rewrites remote history, can destroy collaborators' work.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git push --force*" ||
    context.command like "*git push -f *" ||
    context.command like "*git push * --force*" ||
    context.command like "*git push * -f *"
};

@id("forbid-git-reset-hard")
@description("Block git reset --hard — discards all uncommitted changes irreversibly.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git reset --hard*"
};

@id("forbid-git-clean-force")
@description("Block git clean -f — permanently deletes untracked files.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git clean -f*" ||
    context.command like "*git clean -df*" ||
    context.command like "*git clean -xf*" ||
    context.command like "*git clean -xdf*"
};

@id("forbid-git-checkout-discard")
@description("Block git checkout . — discards all unstaged changes in working tree.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git checkout -- .*" ||
    context.command like "*git checkout .*"
};

@id("forbid-git-restore-discard")
@description("Block git restore . — discards all unstaged changes (modern equivalent of checkout .).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git restore .*" ||
    context.command like "*git restore --staged --worktree *"
};

@id("forbid-git-branch-force-delete")
@description("Block git branch -D — force-deletes branches without merge check, can lose unmerged work.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git branch -D *"
};

@id("forbid-git-rebase-no-verify")
@description("Block git operations with --no-verify — bypasses pre-commit hooks and safety checks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git commit --no-verify*" ||
    context.command like "*git push --no-verify*" ||
    context.command like "*git merge --no-verify*"
};

@id("forbid-git-filter-branch")
@description("Block git filter-branch and filter-repo — rewrites entire repository history.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*git filter-branch*" ||
    context.command like "*git filter-repo*"
};

// ═══════════════════════════════════════════════════════
// §3  Infrastructure Teardown
// ═══════════════════════════════════════════════════════
//
// Block commands that destroy cloud infrastructure,
// containers, and orchestrated services. These can
// take down production systems.

@id("forbid-terraform-destroy")
@description("Block terraform destroy — tears down all managed infrastructure.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*terraform destroy*" ||
    context.command like "*tofu destroy*"
};

@id("forbid-terraform-apply-auto-approve")
@description("Block terraform apply with auto-approve — bypasses human review of infrastructure changes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*terraform apply -auto-approve*" ||
    context.command like "*terraform apply --auto-approve*" ||
    context.command like "*tofu apply -auto-approve*" ||
    context.command like "*tofu apply --auto-approve*"
};

@id("forbid-docker-system-prune")
@description("Block docker system prune — removes all unused containers, images, networks, and volumes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*docker system prune*"
};

@id("forbid-docker-volume-rm")
@description("Block docker volume removal — destroys persistent data in named volumes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*docker volume rm *" ||
    context.command like "*docker volume prune*"
};

@id("forbid-docker-rm-force")
@description("Block force removal of running containers — kills processes without graceful shutdown.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*docker rm -f *" ||
    context.command like "*docker rm --force *"
};

@id("forbid-kubectl-delete-namespace")
@description("Block kubectl delete namespace — destroys all resources in a Kubernetes namespace.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kubectl delete namespace *" ||
    context.command like "*kubectl delete ns *"
};

@id("forbid-kubectl-delete-all")
@description("Block kubectl delete with --all flag — mass-deletes Kubernetes resources.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kubectl delete * --all*"
};

@id("forbid-helm-uninstall")
@description("Block helm uninstall — removes deployed Kubernetes releases and their resources.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*helm uninstall *" ||
    context.command like "*helm delete *"
};

// ═══════════════════════════════════════════════════════
// §4  Database Destruction
// ═══════════════════════════════════════════════════════
//
// Block shell commands that execute destructive SQL or
// database management operations. Covers direct CLI
// invocations and piped SQL.

@id("forbid-drop-database")
@description("Block DROP DATABASE commands — permanently destroys entire databases.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*DROP DATABASE*" ||
    context.command like "*drop database*" ||
    context.command like "*dropdb *"
};

@id("forbid-drop-table")
@description("Block DROP TABLE commands — permanently destroys tables and their data.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*DROP TABLE*" ||
    context.command like "*drop table*"
};

@id("forbid-truncate-table")
@description("Block TRUNCATE TABLE commands — irrecoverably deletes all rows from a table.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*TRUNCATE TABLE*" ||
    context.command like "*TRUNCATE *" ||
    context.command like "*truncate table*"
};

@id("forbid-delete-without-where")
@description("Block DELETE FROM without WHERE clause — deletes all rows in a table.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*DELETE FROM*" &&
    !(context.command like "*WHERE*" || context.command like "*where*")
};

@id("forbid-redis-flushall")
@description("Block Redis FLUSHALL/FLUSHDB — destroys all data in Redis.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*FLUSHALL*" ||
    context.command like "*FLUSHDB*" ||
    context.command like "*flushall*" ||
    context.command like "*flushdb*"
};

@id("forbid-mongo-dropDatabase")
@description("Block MongoDB dropDatabase — permanently destroys a MongoDB database.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*dropDatabase*" ||
    context.command like "*.drop()*"
};

// ═══════════════════════════════════════════════════════
// §5  Package & Dependency Destruction
// ═══════════════════════════════════════════════════════
//
// Guard lock files and dependency manifests from deletion
// or overwrite. Losing lock files causes non-reproducible
// builds and potential supply chain issues.

@id("forbid-delete-lockfile")
@description("Block deletion of package lock files — causes non-reproducible builds.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*package-lock.json" ||
    context.path like "*yarn.lock" ||
    context.path like "*pnpm-lock.yaml" ||
    context.path like "*bun.lockb" ||
    context.path like "*Cargo.lock" ||
    context.path like "*Gemfile.lock" ||
    context.path like "*poetry.lock" ||
    context.path like "*uv.lock" ||
    context.path like "*composer.lock" ||
    context.path like "*go.sum"
};

@id("forbid-shell-rm-lockfile")
@description("Block shell commands that delete lock files — use package manager commands instead.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*rm *package-lock*" ||
     context.command like "*rm *yarn.lock*" ||
     context.command like "*rm *pnpm-lock*" ||
     context.command like "*rm *Cargo.lock*" ||
     context.command like "*rm *poetry.lock*" ||
     context.command like "*rm *uv.lock*" ||
     context.command like "*rm *go.sum*")
};

@id("forbid-shell-rm-node-modules")
@description("Block rm -rf node_modules via shell — use package manager clean commands instead.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -rf *node_modules*" ||
    context.command like "*rm -fr *node_modules*"
};

// ═══════════════════════════════════════════════════════
// §6  Recursive Permission & Ownership Changes
// ═══════════════════════════════════════════════════════
//
// Block broad recursive permission changes that can
// break system security or make files world-readable.

@id("forbid-chmod-recursive-permissive")
@description("Block recursive chmod to overly permissive modes (777, 666) — breaks file security model.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*chmod -R 777 *" ||
    context.command like "*chmod -R 666 *" ||
    context.command like "*chmod -R a+rwx *"
};

@id("forbid-chown-recursive-root")
@description("Block recursive chown to root — can lock out the current user from their own files.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*chown -R root *"
};

// ═══════════════════════════════════════════════════════
// §7  Disk & Partition Operations
// ═══════════════════════════════════════════════════════
//
// Block commands that modify disk partitions or create
// filesystems. An agent should never touch block devices.

@id("forbid-fdisk")
@description("Block fdisk/parted — partition table modification can destroy all data on a disk.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*fdisk *" ||
    context.command like "*parted *" ||
    context.command like "*gdisk *"
};

@id("forbid-wipefs")
@description("Block wipefs — erases filesystem signatures from block devices.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*wipefs *"
};

// ═══════════════════════════════════════════════════════
// §8  Critical File Deletion Guards
// ═══════════════════════════════════════════════════════
//
// Protect critical project and system files from deletion.
// These files are difficult to reconstruct and their loss
// can break builds, deployments, or the entire project.

@id("forbid-delete-gitignore")
@description("Block deletion of .gitignore — can cause secrets and build artifacts to be committed.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.gitignore"
};

@id("forbid-delete-dockerfile")
@description("Block deletion of Dockerfiles — required for container builds and deployments.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*Dockerfile" ||
    context.path like "*docker-compose*.yml" ||
    context.path like "*docker-compose*.yaml"
};

@id("forbid-delete-ci-config")
@description("Block deletion of CI/CD configuration files — breaks automated build and deploy pipelines.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.github/workflows/*.yml" ||
    context.path like "*.github/workflows/*.yaml" ||
    context.path like "*.gitlab-ci.yml" ||
    context.path like "*Jenkinsfile" ||
    context.path like "*.circleci/config.yml"
};

@id("forbid-delete-migration-files")
@description("Block deletion of database migration files — can corrupt migration history and break deployments.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*migrations/*.py" ||
    context.path like "*migrations/*.sql" ||
    context.path like "*migrations/*.rs" ||
    context.path like "*migrations/*.ts" ||
    context.path like "*migrations/*.js"
};

@id("forbid-delete-security-config")
@description("Block deletion of security configuration files — can disable authentication and authorization.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.eslintrc*" ||
    context.path like "*security.yml" ||
    context.path like "*security.yaml" ||
    context.path like "*CODEOWNERS" ||
    context.path like "*.pre-commit-config.yaml"
};

// ═══════════════════════════════════════════════════════
// §9  Kill & Process Termination
// ═══════════════════════════════════════════════════════
//
// Block commands that mass-kill processes. An agent
// should not terminate arbitrary processes.

@id("forbid-killall")
@description("Block killall and pkill — mass process termination can take down critical services.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*killall *" ||
    context.command like "*pkill *"
};

@id("forbid-kill-signal-9")
@description("Block kill -9 — forcibly kills processes without cleanup, can cause data corruption.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kill -9 *" ||
    context.command like "*kill -KILL *" ||
    context.command like "*kill -SIGKILL *"
};

// ═══════════════════════════════════════════════════════
// §10  Destructive + Sensitive Data Compound Guards
// ═══════════════════════════════════════════════════════
//
// Compound policies that combine destructive command
// patterns with sensitivity labels. More restrictive
// when the trajectory carries sensitive data.

@id("forbid-any-destructive-on-confidential-trajectory")
@description("Block non-compliant shell commands when trajectory carries confidential data — defense in depth against destructive actions on sensitive projects.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    !context.policy.compliant &&
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential")
};

@id("forbid-file-delete-on-confidential-trajectory")
@description("Block all file deletions when trajectory carries confidential or higher data — prevents evidence destruction.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.label == Label::"Confidential" ||
    context.label == Label::"HighlyConfidential"
};
