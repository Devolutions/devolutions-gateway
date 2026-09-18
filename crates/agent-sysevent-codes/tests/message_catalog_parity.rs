use std::path::Path;

const EVENTS: &[(u32, usize)] = &[
    (agent_sysevent_codes::POLICY_WRITE_ATTEMPTED, 5),
    (agent_sysevent_codes::POLICY_WRITE_DENIED, 6),
    (agent_sysevent_codes::POLICY_CREATE_FAILED, 8),
    (agent_sysevent_codes::POLICY_CREATE_SUCCEEDED, 11),
    (agent_sysevent_codes::POLICY_CHANGE_FAILED, 8),
    (agent_sysevent_codes::POLICY_CHANGE_SUCCEEDED, 11),
    (agent_sysevent_codes::POLICY_EXTERNAL_CHANGE_APPLIED, 4),
    (agent_sysevent_codes::POLICY_EXTERNAL_CHANGE_REJECTED, 3),
];

#[test]
fn policy_events_match_the_agent_catalog() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devolutions-agent/devolutions-agent.mc");
    let catalog = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    for &(code, insertion_count) in EVENTS {
        let marker = format!("MessageId={code}");
        let start = catalog
            .find(&marker)
            .unwrap_or_else(|| panic!("Agent catalog omits {marker}"));
        let block = &catalog[start
            ..catalog[start..]
                .find("\nMessageId=")
                .map_or(catalog.len(), |end| start + end)];
        let messages: Vec<_> = block
            .lines()
            .enumerate()
            .filter(|(_, line)| line.starts_with("Language="))
            .map(|(index, _)| block.lines().nth(index + 1).unwrap_or_default())
            .collect();
        assert_eq!(messages.len(), 3, "Agent catalog {marker}");
        for message in messages {
            for insertion in 1..=insertion_count {
                assert!(
                    message.contains(&format!("%{insertion}")),
                    "Agent catalog {marker} omits %{insertion}"
                );
            }
            assert!(
                !message.contains(&format!("%{}", insertion_count + 1)),
                "Agent catalog {marker} has an unexpected insertion"
            );
        }
    }
}
