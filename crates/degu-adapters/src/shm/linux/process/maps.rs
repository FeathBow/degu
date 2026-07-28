use super::{HandleProbe, ProbeStep, deadline_elapsed, failure_for, log_probe_error};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

pub(super) fn holds_path(proc_path: &Path, path: &Path, deadline: Option<Instant>) -> HandleProbe {
    let Some(needle) = path.to_str() else {
        return HandleProbe::Failed;
    };
    if deadline_elapsed(deadline) {
        return HandleProbe::Deadline;
    }
    let file = match File::open(proc_path.join("maps")) {
        Ok(file) => file,
        Err(err) => {
            log_probe_error(proc_path, &err, ProbeStep::Maps);
            return failure_for(&err);
        }
    };
    let mut lines = BufReader::new(file).lines();
    loop {
        if deadline_elapsed(deadline) {
            return HandleProbe::Deadline;
        }
        let Some(line) = lines.next() else {
            return HandleProbe::Clear;
        };
        match line {
            Ok(line) if line.contains(needle) => return HandleProbe::Held,
            Ok(_) => {}
            Err(err) => {
                log_probe_error(proc_path, &err, ProbeStep::Maps);
                return failure_for(&err);
            }
        }
    }
}
