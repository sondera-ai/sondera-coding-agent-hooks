use std::env;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=googleapis");
    configure_vendored_protoc()?;

    let proto_root = PathBuf::from("proto");
    let sondera_protos = [
        proto_root.join("sondera/harness/v1/harness.proto"),
        proto_root.join("sondera/harness/v1/trajectory.proto"),
        proto_root.join("sondera/console/v1/agent.proto"),
        proto_root.join("sondera/console/v1/console.proto"),
        proto_root.join("sondera/console/v1/trajectory.proto"),
    ];

    for proto in sondera_protos.iter() {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let include_dir = locate_protoc_include().ok_or_else(|| {
        "sondera-types requires well-known protobuf includes from vendored protoc or an explicit PROTOC_INCLUDE"
            .to_string()
    })?;

    // The vendored protoc ships only `google/protobuf/*`; the AIP annotation
    // protos (`google/api/field_behavior.proto`) are vendored in-repo under
    // `googleapis/` and exported from buf.build/googleapis/googleapis. Both
    // include roots are needed or the annotations fail to resolve at codegen
    // time even though `buf lint` resolves them from its own module deps.
    let googleapis_root = PathBuf::from("googleapis");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .protoc_arg(format!("-I{}", include_dir.display()))
        .compile_protos(&sondera_protos, &[proto_root, googleapis_root])?;

    Ok(())
}

fn configure_vendored_protoc() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // Build scripts run before prost invokes protoc, so set the process env
        // once here while still allowing explicit CI/operator overrides.
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    if env::var_os("PROTOC_INCLUDE").is_none() {
        let include = protoc_bin_vendored::include_path()?;
        // See PROTOC above; prost-build reads PROTOC_INCLUDE during codegen.
        unsafe {
            env::set_var("PROTOC_INCLUDE", include);
        }
    }

    Ok(())
}

fn locate_protoc_include() -> Option<PathBuf> {
    const REQUIRED_FILE: &str = "google/protobuf/timestamp.proto";

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(env_paths) = env::var_os("PROTOC_INCLUDE") {
        candidates.extend(env::split_paths(&env_paths));
    }

    if let Some(prefix_dir) = protoc_prefix_include_dir() {
        candidates.push(prefix_dir);
    }

    candidates.extend(default_include_candidates());

    let mut seen: Vec<PathBuf> = Vec::new();

    for candidate in candidates {
        if candidate.as_os_str().is_empty() {
            continue;
        }
        if seen.iter().any(|existing| existing == &candidate) {
            continue;
        }
        seen.push(candidate.clone());

        if candidate.join(REQUIRED_FILE).exists() {
            return Some(candidate);
        }
    }

    None
}

fn protoc_prefix_include_dir() -> Option<PathBuf> {
    protoc_binary_path().and_then(|path| {
        path.parent()
            .and_then(|bin| bin.parent().map(|prefix| prefix.join("include")))
    })
}

fn protoc_binary_path() -> Option<PathBuf> {
    env::var_os("PROTOC")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| find_in_path("protoc"))
}

fn find_in_path(executable: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(executable);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{executable}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn default_include_candidates() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/usr/include"),
        PathBuf::from("/usr/local/include"),
        PathBuf::from("/usr/local/opt/protobuf/include"),
        PathBuf::from("/opt/homebrew/include"),
        PathBuf::from("/opt/homebrew/opt/protobuf/include"),
        PathBuf::from("/opt/local/include"),
    ];

    if let Ok(target_arch) = env::var("CARGO_CFG_TARGET_ARCH") {
        dirs.push(Path::new("/usr/include").join(format!("{target_arch}-linux-gnu")));
        dirs.push(Path::new("/usr/local/include").join(format!("{target_arch}-linux-gnu")));
    }

    if let Some(home) = env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/include"));
    }

    dirs
}
