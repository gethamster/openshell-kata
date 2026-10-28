//! Local fixture: readonly snapshot responses, not a Kubernetes API implementation.
use std::{fs::OpenOptions, io::Write, path::Path, process};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("UNTRUSTED_MARKER").is_some() {
        process::exit(19);
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    OpenOptions::new()
        .append(true)
        .create(true)
        .open("/fixture-api/calls.log")?
        .write_all(format!("{}\n", args.join(" ")).as_bytes())?;
    let get = args
        .iter()
        .position(|arg| arg == "get")
        .ok_or("missing readonly command")?;
    let resource = args.get(get + 1).ok_or("missing resource")?;
    let namespace = args
        .iter()
        .position(|arg| arg == "-n")
        .and_then(|index| args.get(index + 1))
        .map_or("cluster", String::as_str);
    let name = if resource == "pods" {
        "list"
    } else {
        args.get(get + 2).ok_or("missing name")?
    };
    for value in [resource.as_str(), namespace, name] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        {
            process::exit(23);
        }
    }
    let path = Path::new("/fixture-api").join(format!("{resource}-{namespace}-{name}.json"));
    match std::fs::read(path) {
        Ok(bytes) => std::io::stdout().write_all(&bytes)?,
        Err(_) => process::exit(24),
    };
    Ok(())
}
