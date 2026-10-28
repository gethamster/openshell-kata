//! Assert raw-packet verdicts against already attached task-owned TCX programs.
use std::{fs, path::Path, process::Command};
fn verdict(
    program: &str,
    packet: &Path,
    expected: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("bpftool")
        .args(["-j", "prog", "run", "id", program, "data_in"])
        .arg(packet)
        .args(["repeat", "1"])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let json = String::from_utf8(output.stdout)?;
    let actual = json
        .split("\"retval\":")
        .nth(1)
        .and_then(|part| part.split(',').next())
        .ok_or("retval absent")?
        .parse::<u32>()?;
    if actual != expected {
        return Err(format!(
            "{}: expected {expected}, observed {actual}",
            packet.display()
        )
        .into());
    }
    Ok(format!(
        "{{\"case\":\"{}\",\"expected\":{expected},\"observed\":{actual}}}",
        packet
            .file_stem()
            .ok_or("packet name absent")?
            .to_str()
            .ok_or("non-UTF8 packet path")?
    ))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: run EGRESS_PROGRAM_ID INGRESS_PROGRAM_ID PACKET_DIR".into());
    }
    let root = Path::new(&args[2]);
    let mut paths = fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("invalid packet fixture")?;
        if name.starts_with("ssh-") {
            continue;
        }
        let expected = if name == "broker-allow" { u32::MAX } else { 2 };
        println!("{}", verdict(&args[0], &path, expected)?);
    }
    for (name, program, expected) in [
        ("ssh-syn.bin", &args[1], u32::MAX),
        ("ssh-admitted-reply.bin", &args[0], u32::MAX),
        ("ssh-unadmitted-port.bin", &args[0], 2),
    ] {
        println!("{}", verdict(program, &root.join(name), expected)?);
    }
    Ok(())
}
