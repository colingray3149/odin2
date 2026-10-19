use super::Value;

pub(crate) fn pids(pids: &[u32]) -> Value {
    Value::Array(
        "u".to_owned(),
        pids.iter().map(|pid| Value::Uint32(*pid)).collect(),
    )
}

pub(crate) fn invocation_bytes(bytes: &[u8; 16]) -> Value {
    Value::Array(
        "y".to_owned(),
        bytes.iter().map(|byte| Value::Byte(*byte)).collect(),
    )
}

pub(crate) fn kill_mode_control_group() -> Value {
    Value::String("control-group".to_owned())
}

pub(crate) fn unit_names(names: &[String]) -> Value {
    Value::Array(
        "s".to_owned(),
        names
            .iter()
            .map(|name| Value::String(name.clone()))
            .collect(),
    )
}
pub(crate) fn delegate_false() -> Value {
    Value::Bool(false)
}
