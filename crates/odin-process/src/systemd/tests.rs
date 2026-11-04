use super::{marshal_method_call, parse_message, values, Value, MESSAGE_KIND_METHOD_CALL};

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

#[test]
fn a_unit_reads_as_systemctl_shows_it() {
    use super::ManagerClient;
    use crate::test_support::RegisteredWorkerFixture;

    let manager = RegisteredWorkerFixture::new().expect("fake manager");
    manager.plant_unit(
        "odin-test.service",
        "loaded",
        "active",
        "running",
        &[
            ("Result", Value::String("success".to_owned())),
            ("ExecMainStatus", Value::Int32(0)),
            ("ActiveEnterTimestamp", Value::Uint64(1_789_990_000_000_000)),
        ],
    );
    let mut client = ManagerClient::connect(manager.bus()).expect("client connects");
    let state = super::units::read_unit(&mut client, "odin-test.service").expect("unit reads");
    assert_eq!(state["LoadState"], "loaded");
    assert_eq!(state["ActiveState"], "active");
    assert_eq!(state["Result"], "success");
    assert_eq!(state["ExecMainStatus"], "0");
    assert_eq!(state["ActiveEnterTimestamp"], "@1789990000");
}
