use super::manager::escape_unit_component;
use super::{
    compose_scope_unit_name, marshal_method_call, parse_message, signature_alignment, values,
    BusAddress, Value, MESSAGE_KIND_METHOD_CALL, MESSAGE_KIND_METHOD_RETURN,
};

#[test]
fn escape_matches_systemd_rules() {
    assert_eq!(escape_unit_component("odin"), "odin");
    assert_eq!(escape_unit_component("wp-11a"), "wp\\x2d11a");
    assert_eq!(escape_unit_component("a/b"), "a-b");
    assert_eq!(escape_unit_component(".hidden"), "\\x2ehidden");
    assert_eq!(escape_unit_component("sp ace"), "sp\\x20ace");
    assert_eq!(escape_unit_component("under_score.dot"), "under_score.dot");
    assert_eq!(escape_unit_component("wei\\rd"), "wei\\x5crd");
    assert_eq!(escape_unit_component(""), "");
    assert_eq!(escape_unit_component("ABC123"), "ABC123");
}

#[test]
fn scope_names_follow_the_exact_template() {
    let name = compose_scope_unit_name("tx0123456789abcdef", "wp-11a", 3, "0123abcd");
    assert_eq!(
        name,
        "tx0123456789abcdef-wp\\x2d11a-attempt-3-0123abcd.scope"
    );
    assert!(name.ends_with(".scope"));
    assert!(name.starts_with("tx0123456789abcdef-"));
    assert!(name.contains("-attempt-3-"));
}

#[test]
fn bus_addresses_refuse_unregistered_schemes() {
    assert!(BusAddress::parse("/run/user/1000/bus").is_ok());
    assert!(
        BusAddress::parse("unix:path=/run/user/1000/bus").is_ok(),
        "the exact unix:path spelling must parse"
    );
    assert!(BusAddress::parse("unix:abstract=/tmp/dbus-foo").is_err());
    assert!(BusAddress::parse("tcp:host=127.0.0.1,port=1").is_err());
    assert!(BusAddress::parse("autolaunch:").is_err());
    assert!(BusAddress::parse("unix:dir=/tmp").is_err());
    assert!(BusAddress::parse("unix:path=/a,path=/b").is_err());
    assert!(BusAddress::parse("").is_err());
    assert!(BusAddress::parse("relative/path").is_err());
    assert!(BusAddress::unix_socket("relative".into()).is_err());
    assert!(BusAddress::unix_socket("".into()).is_err());
    assert_eq!(
        BusAddress::parse("unix:path=/run/user/1000/bus"),
        BusAddress::unix_socket("/run/user/1000/bus".into())
    );
    assert_eq!(
        BusAddress::unix_socket("/run/user/1000/bus".into())
            .expect("absolute")
            .to_string(),
        "unix:path=/run/user/1000/bus"
    );
}

#[test]
fn signatures_align_like_the_wire() {
    assert_eq!(signature_alignment("y").unwrap(), 1);
    assert_eq!(signature_alignment("b").unwrap(), 4);
    assert_eq!(signature_alignment("s").unwrap(), 4);
    assert_eq!(signature_alignment("o").unwrap(), 4);
    assert_eq!(signature_alignment("g").unwrap(), 1);
    assert_eq!(signature_alignment("t").unwrap(), 8);
    assert_eq!(signature_alignment("au").unwrap(), 4);
    assert_eq!(signature_alignment("(yv)").unwrap(), 8);
    assert_eq!(signature_alignment("a(yv)").unwrap(), 4);
    assert!(signature_alignment("").is_err());
}

#[test]
fn method_call_roundtrips_through_the_parser() {
    let body = vec![
        Value::String("tx-odin-attempt-1-aa22bb44.scope".to_owned()),
        Value::String("fail".to_owned()),
        Value::Array(
            "(sv)".to_owned(),
            vec![
                Value::Struct(vec![
                    Value::String("PIDs".to_owned()),
                    Value::Variant(Box::new(values::pids(&[4711]))),
                ]),
                Value::Struct(vec![
                    Value::String("KillMode".to_owned()),
                    Value::Variant(Box::new(values::kill_mode_control_group())),
                ]),
                Value::Struct(vec![
                    Value::String("Delegate".to_owned()),
                    Value::Variant(Box::new(values::delegate_false())),
                ]),
                Value::Struct(vec![
                    Value::String("RuntimeMaxUSec".to_owned()),
                    Value::Variant(Box::new(Value::Uint64(30_000_000))),
                ]),
            ],
        ),
        Value::Array("(sa(sv))".to_owned(), Vec::new()),
    ];
    let bytes = marshal_method_call(
        7,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
        &body,
    )
    .expect("marshal call");
    let message = parse_message(&bytes).expect("parse call");
    assert_eq!(message.kind, MESSAGE_KIND_METHOD_CALL);
    assert_eq!(message.serial, 7);
    assert_eq!(message.signature, "ssa(sv)a(sa(sv))");
    assert_eq!(message.error_name, None);
    assert_eq!(message.reply_serial, None);
    let mut cursor = super::WireCursor::new(&message.body);
    let name = cursor.value("s").expect("name");
    assert_eq!(
        name,
        Value::String("tx-odin-attempt-1-aa22bb44.scope".to_owned())
    );
    let mode = cursor.value("s").expect("mode");
    assert_eq!(mode, Value::String("fail".to_owned()));
    let properties = cursor.array("(sv)").expect("properties");
    assert_eq!(properties.len(), 4);
    let Value::Struct(first_property) = &properties[0] else {
        panic!("property must be a struct");
    };
    assert_eq!(first_property[0], Value::String("PIDs".to_owned()));
    let Value::Variant(inner) = &first_property[1] else {
        panic!("property value must be a variant");
    };
    assert_eq!(inner.as_ref(), &values::pids(&[4711]));
    let aux = cursor.array("(sa(sv))").expect("aux");
    assert!(aux.is_empty());
}

#[test]
fn properties_map_roundtrip_decodes_exact_types() {
    // A GetAll-style body: a{sv} with InvocationID (ay), MainPID (u),
    // KillMode (s), Delegate (b), and a ControlGroup object path.
    let mut body = Vec::new();
    let entries = vec![
        Value::Struct(vec![
            Value::String("InvocationID".to_owned()),
            Value::Variant(Box::new(values::invocation_bytes(&[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]))),
        ]),
        Value::Struct(vec![
            Value::String("MainPID".to_owned()),
            Value::Variant(Box::new(Value::Uint32(4242))),
        ]),
        Value::Struct(vec![
            Value::String("KillMode".to_owned()),
            Value::Variant(Box::new(values::kill_mode_control_group())),
        ]),
        Value::Struct(vec![
            Value::String("Delegate".to_owned()),
            Value::Variant(Box::new(values::delegate_false())),
        ]),
        Value::Struct(vec![
            Value::String("ControlGroup".to_owned()),
            Value::Variant(Box::new(Value::ObjectPath(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope".to_owned(),
            ))),
        ]),
    ];
    super::marshal_value(&mut body, &Value::Array("(sv)".to_owned(), entries))
        .expect("marshal reply body");
    let mut cursor = super::WireCursor::new(&body);
    let decoded = cursor.value("a{sv}").expect("decode properties");
    let Value::Array(_, entries) = decoded else {
        panic!("properties must decode as an array");
    };
    assert_eq!(entries.len(), 5);
    let Value::Struct(first) = &entries[0] else {
        panic!("entry must be a struct");
    };
    assert_eq!(first[0], Value::String("InvocationID".to_owned()));
    let Value::Variant(inner) = &first[1] else {
        panic!("InvocationID must be a variant");
    };
    let Value::Array(element, bytes) = inner.as_ref() else {
        panic!("InvocationID must be an ay variant");
    };
    assert_eq!(element, "y");
    assert_eq!(
        bytes,
        &vec![
            Value::Byte(0),
            Value::Byte(1),
            Value::Byte(2),
            Value::Byte(3),
            Value::Byte(4),
            Value::Byte(5),
            Value::Byte(6),
            Value::Byte(7),
            Value::Byte(8),
            Value::Byte(9),
            Value::Byte(10),
            Value::Byte(11),
            Value::Byte(12),
            Value::Byte(13),
            Value::Byte(14),
            Value::Byte(15),
        ]
    );
}

#[test]
fn list_units_row_shape_decodes() {
    let row = Value::Struct(vec![
        Value::String("tx.scope".to_owned()),
        Value::String(String::new()),
        Value::String("loaded".to_owned()),
        Value::String("active".to_owned()),
        Value::String("running".to_owned()),
        Value::String(String::new()),
        Value::ObjectPath("/org/freedesktop/systemd1/unit/tx_2escope".to_owned()),
        Value::Uint32(0),
        Value::String(String::new()),
        Value::ObjectPath("/".to_owned()),
    ]);
    let mut body = Vec::new();
    super::marshal_value(
        &mut body,
        &Value::Array("(ssssssouso)".to_owned(), vec![row]),
    )
    .expect("marshal row");
    let mut cursor = super::WireCursor::new(&body);
    let rows = cursor.array("(ssssssouso)").expect("rows");
    assert_eq!(rows.len(), 1);
    let Value::Struct(columns) = &rows[0] else {
        panic!("row must be a struct");
    };
    assert_eq!(columns.len(), 10);
    assert_eq!(columns[0].as_str(), Some("tx.scope"));
    assert_eq!(columns[3].as_str(), Some("active"));
    assert_eq!(columns[4].as_str(), Some("running"));
    assert_eq!(
        columns[6].as_str(),
        Some("/org/freedesktop/systemd1/unit/tx_2escope")
    );
}

#[test]
fn error_reply_shape_is_decodable() {
    let mut body = Vec::new();
    super::marshal_value(
        &mut body,
        &Value::String("Unit tx.scope already exists.".to_owned()),
    )
    .expect("marshal error body");
    let message = super::Message {
        kind: MESSAGE_KIND_METHOD_RETURN,
        serial: 9,
        path: None,
        interface: None,
        member: None,
        destination: None,
        reply_serial: Some(4),
        error_name: None,
        signature: "s".to_owned(),
        body,
    };
    assert_eq!(message.serial, 9);
    assert_eq!(
        super::decode_error_body(&message),
        "Unit tx.scope already exists."
    );
    let empty = super::Message {
        kind: MESSAGE_KIND_METHOD_RETURN,
        serial: 10,
        path: None,
        interface: None,
        member: None,
        destination: None,
        reply_serial: None,
        error_name: None,
        signature: String::new(),
        body: Vec::new(),
    };
    assert_eq!(super::decode_error_body(&empty), "");
}

#[test]
fn pid_and_invocation_helpers_have_exact_signatures() {
    assert_eq!(values::pids(&[1, 2, 3]).signature(), "au");
    assert_eq!(values::invocation_bytes(&[7; 16]).signature(), "ay");
    assert_eq!(values::kill_mode_control_group().signature(), "s");
    assert_eq!(values::delegate_false().signature(), "b");
}

#[test]
fn truncated_messages_are_rejected_not_invented() {
    let bytes = marshal_method_call(
        1,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
        "",
        &[],
    )
    .expect("marshal hello");
    assert!(parse_message(&bytes).is_ok());
    assert!(parse_message(&bytes[..bytes.len() - 1]).is_err());
    assert!(parse_message(&bytes[..8]).is_err());
    assert!(parse_message(&[]).is_err());
    let mut endian_flipped = bytes.clone();
    endian_flipped[0] = b'B';
    assert!(parse_message(&endian_flipped).is_err());
}
