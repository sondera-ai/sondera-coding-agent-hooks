@id("forbid-rm-system-auth-files")
@description("Block shell deletion of system authentication and integrity files. Parsed commands use exact arguments; parse failures use conservative raw-command matching.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    (
        context has parse && context.parse.ok &&
        context.parse.program_args.containsAny([
            "rm:/etc/passwd", "rm:/etc/shadow", "rm:/etc/gshadow", "rm:/etc/group",
            "rm:/etc/sudoers",
            "rm:~/.ssh/authorized_keys", "rm:~/.ssh/authorized_keys2",
            "rm:/root/.ssh/authorized_keys"
        ])
    )
    ||
    (
        ( (context has parse && !context.parse.ok) || !(context has parse) ) &&
        context.command like "*rm *" &&
        (
            context.command like "*/etc/passwd*" ||
            context.command like "*/etc/shadow*" ||
            context.command like "*/etc/gshadow*" ||
            context.command like "*/etc/group*" ||
            context.command like "*/etc/sudoers*" ||
            context.command like "*.ssh/authorized_keys*"
        )
    )
};
