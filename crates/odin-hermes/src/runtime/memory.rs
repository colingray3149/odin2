//! Explicit memory edits through the brain write path.

use std::sync::Arc;

use odin_brain::learn::{Edit, EditAction, EditScope, EntryKind, Namespaces, Provenance};
use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::review::ReviewMutation;

const TITLE_WORDS: usize = 8;
const REMEMBER_KEYS: &[&str] = &["content", "title", "about"];

fn matches_exact_phrase(text: &str, phrase: &str) -> bool {
    let token_char =
        |character: char| character.is_alphanumeric() || matches!(character, '-' | '_');
    text.match_indices(phrase).any(|(start, _)| {
        text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !token_char(c))
            && text[start + phrase.len()..]
                .chars()
                .next()
                .is_none_or(|c| !token_char(c))
    })
}

fn seat_of(scope: &Scope, tool: &'static str) -> Result<odin_domain::SeatId, HostToolError> {
    scope.seat.clone().ok_or(HostToolError::Scope {
        tool,
        reason: "a bound seat is required",
    })
}

fn provenance(scope: &Scope, seat: &odin_domain::SeatId, trigger: &str) -> Provenance {
    Provenance {
        seat: seat.to_string(),
        session: scope
            .session
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        trigger: trigger.to_owned(),
    }
}

fn scope_of(namespaces: &Namespaces, namespace: &str) -> EditScope {
    if namespaces.colin.as_deref() == Some(namespace) {
        EditScope::Colin
    } else if namespaces.project.as_deref() == Some(namespace) {
        EditScope::Project
    } else {
        EditScope::Seat
    }
}

// Refresh served sources after a memory write.
fn refresh(
    runtime: &super::HermesRuntime,
    scope: &Scope,
    seat: &odin_domain::SeatId,
    pages: &[String],
) -> Option<String> {
    let session = scope.session.as_ref()?;
    let (Some(vault), Some(gate)) = (runtime.vault().as_ref(), runtime.vault_write_gate()) else {
        return Some("no vault scoping gate is composed".to_owned());
    };
    let generated = &vault.config().generated_namespace;
    let profile = runtime.profile_namespace();
    pages
        .iter()
        .filter(|page| {
            profile
                .as_ref()
                .is_none_or(|namespace| !page.starts_with(&format!("{namespace}/")))
        })
        .find_map(|page| {
            let page = format!(
                "{generated}/{}/{page}",
                odin_brain::source::silverbullet::RESERVED_MEMORY_SEGMENT
            );
            gate.generated_written(seat, session, vault.config().source_id.as_str(), &page)
                .err()
                .map(|error| error.to_string())
        })
}

pub(super) fn memory_remember_tool(
    runtime: std::sync::Weak<super::HermesRuntime>,
) -> Arc<dyn HostTool> {
    const TOOL: &str = "memory_remember";
    let handler = move |scope: Scope, arguments: Value| -> Result<Value, HostToolError> {
        let unavailable = |reason: String| HostToolError::Unavailable { tool: TOOL, reason };
        if let Some(key) = arguments.as_object().and_then(|object| {
            object
                .keys()
                .find(|key| !REMEMBER_KEYS.contains(&key.as_str()))
        }) {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!("{key:?} is not a memory_remember argument"),
            });
        }
        for key in ["title", "about"] {
            if let Some(value) = arguments.get(key).filter(|value| !value.is_null()) {
                if value.as_str().is_none_or(|value| value.trim().is_empty()) {
                    return Err(HostToolError::Arguments {
                        tool: TOOL,
                        detail: format!("{key} must be a non-empty string"),
                    });
                }
            }
        }
        let text = |key: &str| arguments.get(key).and_then(Value::as_str).map(str::trim);
        let content = text("content")
            .filter(|content| !content.is_empty())
            .ok_or_else(|| HostToolError::Arguments {
                tool: TOOL,
                detail: "content must contain the one fact to keep".to_owned(),
            })?;
        let seat = seat_of(&scope, TOOL)?;
        let runtime = runtime
            .upgrade()
            .ok_or_else(|| unavailable("the Hermes runtime has stopped".to_owned()))?;
        let namespaces = runtime.namespaces(&seat, scope.project.as_ref());
        let edit_scope = match text("about") {
            Some("colin") => EditScope::Colin,
            Some("seat") => EditScope::Seat,
            Some("project") if namespaces.project.is_some() => EditScope::Project,
            None if namespaces.project.is_some() => EditScope::Project,
            None => EditScope::Seat,
            Some(other) => {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("about {other:?} is not one of this session's memories"),
                })
            }
        };
        let title = text("title").map(str::to_owned).unwrap_or_else(|| {
            content
                .split_whitespace()
                .take(TITLE_WORDS)
                .collect::<Vec<_>>()
                .join(" ")
        });
        let edit = Edit {
            action: EditAction::Add,
            kind: EntryKind::Memory,
            scope: edit_scope,
            id: None,
            title,
            content: content.to_owned(),
            evidence: format!("{TOOL} asked by the session"),
        };
        let state = runtime
            .brain_state()
            .map_err(|error| unavailable(error.to_string()))?;
        let (learned, refused) = runtime
            .learn(
                ReviewMutation::acquire(),
                &state,
                &namespaces,
                &[edit],
                &provenance(&scope, &seat, "memory.remember"),
                scope.project.as_ref(),
            )
            .map_err(|error| unavailable(error.to_string()))?;
        if let Some(reason) = refused.into_iter().next() {
            return Err(unavailable(reason));
        }
        let Some(applied) = learned.into_iter().next() else {
            return Ok(json!({ "remembered": true, "alreadyKnown": true }));
        };
        let mut receipt = json!({
            "remembered": true,
            "page": applied.page,
            "commit": applied.commit,
        });
        if let Some(error) = refresh(&runtime, &scope, &seat, &[applied.page]) {
            receipt["knowledgeRefreshUnavailable"] = Value::String(error);
        }
        Ok(receipt)
    };
    Arc::new(super::tools::CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Remember for later sessions".into(),
            description: "Stores a fact or lesson for later sessions. Use about=colin for \
                          personal facts, seat for working preferences, or project for the \
                          current project (the default when it has its own memory)."
                .into(),
            parameters: json!({"type":"object","additionalProperties":false,
                "properties":{
                    "content":{"type":"string","minLength":1,"maxLength":600},
                    "title":{"type":"string","minLength":1,"maxLength":80},
                    "about":{"type":"string","enum":["colin","seat","project"]}},
                "required":["content"]}),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    ))
}

pub(super) fn memory_forget_tool(
    runtime: std::sync::Weak<super::HermesRuntime>,
) -> Arc<dyn HostTool> {
    const TOOL: &str = "memory_forget";
    let handler = move |scope: Scope, arguments: Value| -> Result<Value, HostToolError> {
        let unavailable = |reason: String| HostToolError::Unavailable { tool: TOOL, reason };
        if let Some(key) = arguments.as_object().and_then(|object| {
            object
                .keys()
                .find(|key| !["contains", "commit", "page", "label"].contains(&key.as_str()))
        }) {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!("{key:?} is not a memory_forget argument"),
            });
        }
        if arguments.get("commit").is_some()
            || arguments.get("page").is_some()
            || arguments.get("label").is_some()
        {
            if arguments.as_object().is_none_or(|object| {
                object
                    .keys()
                    .any(|key| !["commit", "page", "label"].contains(&key.as_str()))
            }) {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: "exact forgetting accepts only commit, page and label".to_owned(),
                });
            }
            let required = |key: &str| {
                arguments
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| HostToolError::Arguments {
                        tool: TOOL,
                        detail: format!("exact forgetting requires {key}"),
                    })
            };
            let commit = required("commit")?;
            let page = required("page")?;
            let label = required("label")?;
            let seat = seat_of(&scope, TOOL)?;
            let runtime = runtime
                .upgrade()
                .ok_or_else(|| unavailable("the Hermes runtime has stopped".to_owned()))?;
            let namespaces = runtime.namespaces(&seat, scope.project.as_ref());
            if !namespaces.writable().any(|namespace| {
                page.strip_prefix(namespace)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|rest| !rest.contains('/') && rest.ends_with(".md"))
            }) {
                return Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: "page is outside this session's memories".to_owned(),
                });
            }
            let inverse = {
                let _mutation = ReviewMutation::acquire();
                runtime
                    .brain_state()
                    .map_err(|error| unavailable(error.to_string()))?
                    .revert_exact(page, commit, label, seat.as_str())
                    .map_err(|error| unavailable(error.to_string()))?
            };
            runtime
                .journal_learned(
                    &provenance(&scope, &seat, "memory.forget"),
                    scope.project.as_ref(),
                    &inverse,
                )
                .map_err(|error| {
                    unavailable(format!(
                        "inverse {} of {commit} is committed, but its brain.learned audit \
                         row was not recorded ({error}); retry this same exact request to \
                         record it",
                        inverse.commit
                    ))
                })?;
            let mut receipt = json!({"reverted":true,"retired":[{
                "page":page,"excerpt":label,"commit":inverse.commit,"reverts":commit
            }]});
            if let Some(error) = refresh(&runtime, &scope, &seat, &[page.to_owned()]) {
                receipt["knowledgeRefreshUnavailable"] = Value::String(error);
            }
            tracing::info!(
                "odind: memory.forget.exact {}",
                json!({
                    "seat": seat,
                    "session": scope.session,
                    "project": scope.project,
                    "arguments": arguments,
                    "receipt": receipt,
                })
            );
            return Ok(receipt);
        }
        let phrase = arguments
            .get("contains")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|phrase| (6..=500).contains(&phrase.chars().count()))
            .ok_or_else(|| HostToolError::Arguments {
                tool: TOOL,
                detail: "contains must be 6..=500 characters of exact, case-sensitive text"
                    .to_owned(),
            })?;
        let seat = seat_of(&scope, TOOL)?;
        let runtime = runtime
            .upgrade()
            .ok_or_else(|| unavailable("the Hermes runtime has stopped".to_owned()))?;
        let namespaces = runtime.namespaces(&seat, scope.project.as_ref());
        let state = runtime
            .brain_state()
            .map_err(|error| unavailable(error.to_string()))?;
        // Keep selection and mutation on the same page state.
        let mutation = ReviewMutation::acquire();
        let mut candidates = Vec::new();
        for namespace in namespaces.writable() {
            for entry in state
                .entries(namespace)
                .map_err(|error| unavailable(error.to_string()))?
            {
                let text = format!(
                    "{}\n{}",
                    entry.title.as_deref().unwrap_or_default(),
                    entry.body
                );
                if matches_exact_phrase(&text, phrase) {
                    candidates.push((namespace, entry));
                }
            }
        }
        let [(namespace, entry)] = candidates.as_slice() else {
            let choices = candidates
                .iter()
                .map(|(namespace, entry)| {
                    json!({
                        "page": format!("{namespace}/{}.md", entry.id),
                        "title": entry.title,
                        "excerpt": entry.body.chars().take(160).collect::<String>(),
                    })
                })
                .collect::<Vec<_>>();
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!(
                    "contains {phrase:?} matched {} memories; expected exactly one. Candidates: {}",
                    candidates.len(),
                    json!(choices)
                ),
            });
        };
        let page = format!("{namespace}/{}.md", entry.id);
        let learned = state
            .learned_entry(&page, &phrase.to_lowercase())
            .map_err(|error| unavailable(error.to_string()))?;
        let edit = Edit {
            action: if learned {
                EditAction::Revert
            } else {
                EditAction::Retire
            },
            kind: entry.kind,
            scope: scope_of(&namespaces, namespace),
            id: Some(entry.id.clone()),
            title: String::new(),
            content: String::new(),
            evidence: format!("{TOOL} {phrase:?}"),
        };
        let (learned, refused) = runtime
            .learn(
                mutation,
                &state,
                &namespaces,
                &[edit],
                &provenance(&scope, &seat, "memory.forget"),
                scope.project.as_ref(),
            )
            .map_err(|error| unavailable(error.to_string()))?;
        if learned.is_empty() {
            return Err(unavailable(refused.join("; ")));
        }
        let pages: Vec<String> = learned.iter().map(|applied| applied.page.clone()).collect();
        let mut receipt = json!({
            "retired": learned
                .iter()
                .map(|applied| json!({
                    "page": applied.page,
                    "excerpt": entry.body.chars().take(160).collect::<String>(),
                    "commit": applied.commit,
                }))
                .collect::<Vec<_>>(),
        });
        if let Some(error) = refresh(&runtime, &scope, &seat, &pages) {
            receipt["knowledgeRefreshUnavailable"] = Value::String(error);
        }
        Ok(receipt)
    };
    Arc::new(super::tools::CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Forget a lesson".into(),
            description: "Forgets exactly one memory matching contains, an exact case-sensitive \
                          token or phrase, not a substring of a token. Ambiguous matches are \
                          listed and refused. Corrections use memory_remember after forgetting. \
                          To invert one labelled learning edit, provide commit, page and label \
                          instead of contains; conflicts are refused."
                .into(),
            parameters: json!({"type":"object","additionalProperties":false,
                "properties":{
                    "contains":{"type":"string","minLength":6,"maxLength":500,"description":"Exact case-sensitive token or phrase identifying one memory."},
                    "commit":{"type":"string","pattern":"^[0-9a-fA-F]{40}$"},
                    "page":{"type":"string","minLength":1},
                    "label":{"type":"string","minLength":6,"maxLength":500}},
                "oneOf":[{"required":["contains"],"not":{"anyOf":[
                    {"required":["commit"]},{"required":["page"]},{"required":["label"]}]}},
                    {"required":["commit","page","label"],"not":{"required":["contains"]}}]}),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use odin_ledger::Ledger;
    use odin_omp::host_tools::{HostInvocation, HostTool};
    use serde_json::json;

    fn runtime(root: &std::path::Path) -> Arc<super::super::HermesRuntime> {
        runtime_with_purchase(root, Ledger::open_in_memory().unwrap())
    }

    fn runtime_with_purchase(
        root: &std::path::Path,
        purchase: Ledger,
    ) -> Arc<super::super::HermesRuntime> {
        let vault_root = root.join("vault");
        std::fs::create_dir_all(&vault_root).unwrap();
        let vault = crate::vault::VaultConfig {
            vault_root,
            source_id: "atlas.personal".to_owned(),
            silverbullet: None,
            general_namespaces: vec!["knowledge".to_owned()],
            generated_namespace: "generated".to_owned(),
            excluded_namespaces: Vec::new(),
            max_pages: 100,
            max_page_bytes: 64 * 1024,
            timeout_ms: 1_000,
        };
        let opened = super::super::HermesRuntime::open(
            crate::config::HermesSettings::new(
                root.join("hermes"),
                None,
                Some(vault),
                None,
                vec![],
            )
            .unwrap(),
            super::super::HermesLedgers {
                conversation: Ledger::open_in_memory().unwrap(),
                adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
                purchase: Arc::new(std::sync::Mutex::new(purchase)),
            },
            &BTreeMap::new(),
            None,
            8192,
            BTreeMap::new(),
            None,
        )
        .unwrap();
        opened.set_memory_grants(BTreeMap::from([(
            odin_domain::SeatId::new("sinmara").unwrap(),
            super::super::MemoryGrant {
                own: true,
                profile: Some("colin".to_owned()),
            },
        )]));
        opened.set_profile_namespace(Some("colin".to_owned()));
        opened
    }

    #[test]
    fn remember_and_forget_write_through_the_brain_with_a_commit_each() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let scope = odin_domain::Scope {
            seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
            ..Default::default()
        };
        let invoke = |tool: &Arc<dyn HostTool>, arguments| {
            tool.invoke(HostInvocation {
                scope: scope.clone(),
                arguments,
            })
        };
        let fact = json!({"content": "Colin's favourite tea is oolong", "about": "colin"});
        let receipt = invoke(&remember, fact.clone()).unwrap();
        assert_eq!(receipt["remembered"], true, "{receipt}");
        let page = receipt["page"].as_str().unwrap().to_owned();
        assert!(page.starts_with("colin/memory-"), "{page}");
        let path = root.path().join("vault/generated/memories").join(&page);
        assert!(std::fs::read_to_string(&path).unwrap().contains("oolong"));
        let again = invoke(&remember, fact).unwrap();
        assert_eq!(again["alreadyKnown"], true, "{again}");
        assert!(
            invoke(
                &remember,
                json!({"content": "x", "page_name": "colin/x.md"})
            )
            .is_err(),
            "the destination is never a model argument"
        );

        let receipt = invoke(&forget, json!({"contains": "oolong"})).unwrap();
        assert_eq!(receipt["retired"][0]["page"], page.as_str(), "{receipt}");
        assert!(!path.exists(), "forgetting a learned entry reverts its add");
        let learned = runtime
            .purchase_ledger
            .lock()
            .unwrap()
            .audit_events_after(0, 16)
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == super::super::review::LEARNED_AUDIT_KIND)
            .count();
        assert_eq!(learned, 2, "the remember and its revert are one row each");
    }

    #[test]
    fn remember_rejects_invalid_optional_strings() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        for field in ["title", "about"] {
            for value in [json!(""), json!(false)] {
                let mut arguments = json!({"content":"A valid remembered fact"});
                arguments[field] = value;
                let error = remember
                    .invoke(HostInvocation {
                        scope: odin_domain::Scope {
                            seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                            ..Default::default()
                        },
                        arguments,
                    })
                    .unwrap_err();
                assert!(error.to_string().contains(field), "{error}");
            }
        }
        assert!(learned_rows(&runtime).is_empty());
    }

    #[test]
    fn forget_refuses_ambiguous_tokens_without_changing_any_memory() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let invoke = |tool: &Arc<dyn HostTool>, arguments| {
            tool.invoke(HostInvocation {
                scope: odin_domain::Scope {
                    seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                    ..Default::default()
                },
                arguments,
            })
        };
        let first = invoke(
            &remember,
            json!({"content":"shared-token is in the first memory", "title":"First"}),
        )
        .unwrap();
        let second = invoke(
            &remember,
            json!({"content":"shared-token is in the second memory", "title":"Second"}),
        )
        .unwrap();
        let longer = invoke(
            &remember,
            json!({"content":"shared-token-extra is a distinct token", "title":"Longer"}),
        )
        .unwrap();
        let head = brain_head(root.path());
        let rows = learned_rows(&runtime);
        let error = invoke(&forget, json!({"contains":"shared-token"}))
            .unwrap_err()
            .to_string();
        for receipt in [&first, &second] {
            assert!(error.contains(receipt["page"].as_str().unwrap()), "{error}");
        }
        assert!(!error.contains(longer["page"].as_str().unwrap()), "{error}");
        assert_eq!(brain_head(root.path()), head);
        assert_eq!(learned_rows(&runtime), rows);
        let forgotten = invoke(&forget, json!({"contains":"shared-token-extra"})).unwrap();
        assert_eq!(forgotten["retired"].as_array().unwrap().len(), 1);
        assert_eq!(forgotten["retired"][0]["page"], longer["page"]);
        for receipt in [&first, &second] {
            assert!(root
                .path()
                .join("vault/generated/memories")
                .join(receipt["page"].as_str().unwrap())
                .exists());
        }
    }

    #[test]
    fn forget_by_phrase_does_not_search_an_ungranted_namespace() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let invoke = |seat: &str, tool: &Arc<dyn HostTool>, arguments| {
            tool.invoke(HostInvocation {
                scope: odin_domain::Scope {
                    seat: Some(odin_domain::SeatId::new(seat).unwrap()),
                    ..Default::default()
                },
                arguments,
            })
        };
        let planted = invoke(
            "sinmara",
            &remember,
            json!({"content": "uniquephrase belongs to the profile", "about": "colin"}),
        )
        .unwrap();
        let page = planted["page"].as_str().unwrap().to_owned();
        let path = root.path().join("vault/generated/memories").join(&page);
        runtime.set_memory_grants(BTreeMap::from([(
            odin_domain::SeatId::new("gungnir").unwrap(),
            super::super::MemoryGrant {
                own: true,
                profile: None,
            },
        )]));
        let missed = invoke("gungnir", &forget, json!({"contains": "uniquephrase"}));
        assert!(
            missed.is_err(),
            "an ungranted namespace is not this seat's lessons"
        );
        assert!(path.exists(), "the profile page is unchanged");
        invoke(
            "gungnir",
            &remember,
            json!({"content": "uniquephrase is this seat's own lesson", "about": "seat"}),
        )
        .unwrap();
        let receipt = invoke("gungnir", &forget, json!({"contains": "uniquephrase"})).unwrap();
        assert!(
            receipt["retired"][0]["page"]
                .as_str()
                .unwrap()
                .starts_with("gungnir/"),
            "{receipt}"
        );
        assert!(
            path.exists(),
            "forgetting the seat lesson leaves the profile page"
        );
    }

    #[test]
    fn remembering_a_changed_fact_under_its_title_updates_the_page() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let invoke = |content: &str| {
            remember.invoke(HostInvocation {
                scope: odin_domain::Scope {
                    seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                    ..Default::default()
                },
                arguments: json!({"content": content, "title": "Favourite tea", "about": "colin"}),
            })
        };
        let first = invoke("Colin's favourite tea is oolong").unwrap();
        let second = invoke("Colin's favourite tea is sencha").unwrap();
        assert_eq!(second["remembered"], true, "{second}");
        assert_eq!(second["page"], first["page"]);
        let path = root
            .path()
            .join("vault/generated/memories")
            .join(second["page"].as_str().unwrap());
        assert!(std::fs::read_to_string(&path).unwrap().contains("sencha"));
    }

    #[test]
    fn exact_forget_restores_standing_fact_and_rejects_foreign_scope() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let scope = odin_domain::Scope {
            seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
            ..Default::default()
        };
        let remember_fact = |content: &str| {
            remember.invoke(HostInvocation {
            scope: scope.clone(),
            arguments: json!({"content":content,"title":"Standing preference","about":"colin"}),
        }).unwrap()
        };
        let prior = remember_fact("A real standing preference");
        let state = runtime.brain_state().unwrap();
        let path = state.work_tree().join(prior["page"].as_str().unwrap());
        let original = std::fs::read(&path).unwrap();
        let own = remember_fact("fixture-unique-abc changed preference");
        let arguments =
            json!({"commit":own["commit"],"page":own["page"],"label":"fixture-unique-abc"});
        let foreign_scope = odin_domain::Scope {
            seat: Some(odin_domain::SeatId::new("gungnir").unwrap()),
            ..Default::default()
        };
        assert!(forget
            .invoke(HostInvocation {
                scope: foreign_scope,
                arguments: arguments.clone()
            })
            .is_err());
        let mut wrong_page = arguments.clone();
        wrong_page["page"] = json!("foreign/page.md");
        assert!(forget
            .invoke(HostInvocation {
                scope: scope.clone(),
                arguments: wrong_page
            })
            .is_err());
        let receipt = forget
            .invoke(HostInvocation {
                scope: scope.clone(),
                arguments: arguments.clone(),
            })
            .unwrap();
        assert_eq!(receipt["reverted"], true);
        assert_eq!(receipt["retired"][0]["reverts"], own["commit"]);
        assert!(
            receipt.get("cleanupComplete").is_none(),
            "an inverse does not prove the review barrier"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let retry = forget.invoke(HostInvocation { scope, arguments }).unwrap();
        assert_eq!(retry["retired"], receipt["retired"]);
    }

    #[test]
    fn an_owner_only_phrase_does_not_undo_an_unrelated_learned_update() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let scope = odin_domain::Scope {
            seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
            ..Default::default()
        };
        let invoke = |tool: &Arc<dyn HostTool>, arguments| {
            tool.invoke(HostInvocation {
                scope: scope.clone(),
                arguments,
            })
        };
        let context = (0..16)
            .map(|line| format!("unchanged context line {line}\n"))
            .collect::<String>();
        let fact = |first: &str| {
            json!({
                "title": "Phrase target selection",
                "content": format!("{first}\n{context}\nowner section: unchanged"),
                "about": "colin"
            })
        };
        invoke(&remember, fact("learned earlier preference")).unwrap();
        let updated = invoke(&remember, fact("learned current preference")).unwrap();
        let path = root
            .path()
            .join("vault/generated/memories")
            .join(updated["page"].as_str().unwrap());
        let owner = std::fs::read_to_string(&path).unwrap().replace(
            "owner section: unchanged",
            "owner-only-needle belongs to the owner",
        );
        std::fs::write(&path, &owner).unwrap();
        runtime.brain_state().unwrap().commit_pending().unwrap();
        let head = brain_head(root.path());
        let audit_ids = || {
            learned_rows(&runtime)
                .into_iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>()
        };
        let before = audit_ids();
        let result = invoke(&forget, json!({"contains": "owner-only-needle"}));
        assert!(
            result.is_err(),
            "an unrelated inverse is not a correction: {result:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), owner);
        assert_eq!(brain_head(root.path()), head);
        assert_eq!(audit_ids(), before);
    }

    #[test]
    fn a_metadata_only_phrase_does_not_undo_a_learned_update() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
        let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
        let seat = odin_domain::SeatId::new("sinmara").unwrap();
        let scope = odin_domain::Scope {
            seat: Some(seat.clone()),
            ..Default::default()
        };
        let invoke = |tool: &Arc<dyn HostTool>, arguments| {
            tool.invoke(HostInvocation {
                scope: scope.clone(),
                arguments,
            })
        };
        let context = (0..16)
            .map(|line| format!("unchanged context line {line}\n"))
            .collect::<String>();
        let content = |first: &str| format!("{first}\n{context}\nowner section: unchanged");
        let added = invoke(
            &remember,
            json!({
                "title": "Metadata boundary",
                "content": content("learned earlier preference"),
                "about": "colin"
            }),
        )
        .unwrap();
        let page = added["page"].as_str().unwrap();
        let state = runtime.brain_state().unwrap();
        let (learned, refused) = runtime
            .learn(
                super::ReviewMutation::acquire(),
                &state,
                &runtime.namespaces(&seat, None),
                &[super::Edit {
                    action: super::EditAction::Update,
                    kind: super::EntryKind::Memory,
                    scope: super::EditScope::Colin,
                    id: page
                        .strip_prefix("colin/")
                        .and_then(|leaf| leaf.strip_suffix(".md"))
                        .map(str::to_owned),
                    title: "Metadata boundary".to_owned(),
                    content: content("learned current preference"),
                    evidence: "metadata-only-needle from a review".to_owned(),
                }],
                &super::provenance(&scope, &seat, "turn"),
                None,
            )
            .unwrap();
        assert!(refused.is_empty() && learned.len() == 1, "{refused:?}");
        let path = state.work_tree().join(page);
        let owner = std::fs::read_to_string(&path).unwrap().replace(
            "owner section: unchanged",
            "owner notes metadata-only-needle",
        );
        std::fs::write(&path, &owner).unwrap();
        state.commit_pending().unwrap();
        let head = brain_head(root.path());
        let rows = learned_rows(&runtime);
        let result = invoke(&forget, json!({"contains": "metadata-only-needle"}));
        assert!(
            result.is_err(),
            "evidence is not the visible lesson: {result:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), owner);
        assert_eq!(brain_head(root.path()), head);
        assert_eq!(learned_rows(&runtime), rows);
    }

    #[test]
    fn a_phrase_spanning_lines_or_title_and_body_reverts_its_learned_add() {
        for phrase in ["fixture line\nSecond", "lesson\nfirst fixture"] {
            let root = tempfile::tempdir().unwrap();
            let runtime = runtime(root.path());
            let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
            let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
            let scope = odin_domain::Scope {
                seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                ..Default::default()
            };
            let invoke = |tool: &Arc<dyn HostTool>, arguments| {
                tool.invoke(HostInvocation {
                    scope: scope.clone(),
                    arguments,
                })
            };
            let receipt = invoke(
                &remember,
                json!({
                    "title": "Multiline lesson",
                    "content": "first fixture line\nSecond Fixture line",
                    "about": "colin"
                }),
            )
            .unwrap();
            let path = root
                .path()
                .join("vault/generated/memories")
                .join(receipt["page"].as_str().unwrap());
            let forgotten = invoke(&forget, json!({ "contains": phrase })).unwrap();
            assert_eq!(
                forgotten["retired"][0]["page"], receipt["page"],
                "{phrase:?}"
            );
            assert!(!path.exists(), "{phrase:?}: the learned add is inverted");
            assert_eq!(learned_rows(&runtime).len(), 2, "{phrase:?}");
        }
    }

    #[test]
    fn a_conflicting_owner_edit_is_not_retired_when_its_inverse_is_refused() {
        for synced in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let runtime = runtime(root.path());
            let remember = super::memory_remember_tool(Arc::downgrade(&runtime));
            let forget = super::memory_forget_tool(Arc::downgrade(&runtime));
            let scope = odin_domain::Scope {
                seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                ..Default::default()
            };
            let receipt = remember
                .invoke(HostInvocation {
                    scope: scope.clone(),
                    arguments: json!({
                        "content": "needle learned original",
                        "title": "Preserved owner edit",
                        "about": "colin"
                    }),
                })
                .unwrap();
            let path = root
                .path()
                .join("vault/generated/memories")
                .join(receipt["page"].as_str().unwrap());
            let owner = std::fs::read_to_string(&path)
                .unwrap()
                .replace("needle learned original", "needle owner replacement");
            std::fs::write(&path, &owner).unwrap();
            if synced {
                runtime.brain_state().unwrap().commit_pending().unwrap();
            }
            let head = brain_head(root.path());
            let rows = learned_rows(&runtime)
                .into_iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>();
            let result = forget.invoke(HostInvocation {
                scope,
                arguments: json!({"contains": "needle"}),
            });
            assert!(result.is_err(), "synced={synced}: {result:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), owner);
            assert_eq!(brain_head(root.path()), head);
            assert_eq!(
                learned_rows(&runtime)
                    .into_iter()
                    .map(|event| event.event_id)
                    .collect::<Vec<_>>(),
                rows
            );
        }
    }

    fn brain_head(root: &std::path::Path) -> String {
        let output = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(root.join("hermes/brain.git"))
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn learned_rows(runtime: &super::super::HermesRuntime) -> Vec<odin_ledger::audit::AuditEvent> {
        runtime
            .purchase_ledger
            .lock()
            .unwrap()
            .audit_events_after(0, 64)
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == super::super::review::LEARNED_AUDIT_KIND)
            .collect()
    }

    #[test]
    fn forget_journals_its_inverse_once_and_exact_retry_repairs_a_lost_row() {
        for initially_exact in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let ledger = root.path().join("authority.sqlite");
            let first = runtime_with_purchase(root.path(), Ledger::open(&ledger).unwrap());
            let remember = super::memory_remember_tool(Arc::downgrade(&first));
            let forget = super::memory_forget_tool(Arc::downgrade(&first));
            let scope = odin_domain::Scope {
                seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                ..Default::default()
            };
            let invoke = |tool: &Arc<dyn HostTool>, arguments| {
                tool.invoke(HostInvocation {
                    scope: scope.clone(),
                    arguments,
                })
            };
            let fact = |content: &str| json!({"content": content, "title": "Standing preference", "about": "colin"});
            let prior = invoke(&remember, fact("A real standing preference")).unwrap();
            let path = root
                .path()
                .join("vault/generated/memories")
                .join(prior["page"].as_str().unwrap());
            let original = std::fs::read(&path).unwrap();
            let own = invoke(&remember, fact("fixture-unique-m2a changed preference")).unwrap();
            assert_eq!(own["page"], prior["page"]);
            assert_eq!(learned_rows(&first).len(), 2);
            let arguments = json!({"commit": own["commit"], "page": own["page"], "label": "fixture-unique-m2a"});

            first
                .purchase_ledger
                .lock()
                .unwrap()
                .connection()
                .execute_batch(
                    "CREATE TEMP TRIGGER fixture_audit_outage BEFORE INSERT ON audit_events
                 WHEN NEW.kind = 'brain.learned'
                 BEGIN SELECT RAISE(ABORT, 'fixture audit outage'); END;",
                )
                .unwrap();
            let first_arguments = if initially_exact {
                arguments.clone()
            } else {
                json!({"contains": "fixture-unique-m2a"})
            };
            assert!(
                invoke(&forget, first_arguments).is_err(),
                "an inverse without its audit row is not a clean receipt"
            );
            let inverse = brain_head(root.path());
            assert_ne!(own["commit"], inverse.as_str(), "the inverse did commit");
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(learned_rows(&first).len(), 2);
            first
                .purchase_ledger
                .lock()
                .unwrap()
                .connection()
                .execute_batch("DROP TRIGGER temp.fixture_audit_outage")
                .unwrap();

            let receipt = invoke(&forget, arguments.clone()).unwrap();
            assert_eq!(receipt["retired"][0]["commit"], inverse.as_str());
            assert_eq!(receipt["retired"][0]["reverts"], own["commit"]);
            let again = invoke(&forget, arguments.clone()).unwrap();
            assert_eq!(again["retired"], receipt["retired"]);
            assert_eq!(
                brain_head(root.path()),
                inverse,
                "a retry never inverts again"
            );
            let rows = learned_rows(&first);
            let inverse_rows: Vec<_> = rows
                .iter()
                .filter(|event| event.payload["commit"] == inverse.as_str())
                .collect();
            let [row] = inverse_rows.as_slice() else {
                panic!("exactly one row for the inverse: {rows:?}");
            };
            assert_eq!(row.payload["page"], own["page"]);
            assert_eq!(row.payload["action"], "revert");
            assert_eq!(
                row.scope.seat.as_ref().map(odin_domain::SeatId::as_str),
                Some("sinmara")
            );
            assert_eq!(rows.len(), 3);

            drop((remember, forget, first));
            let reopened = runtime_with_purchase(root.path(), Ledger::open(&ledger).unwrap());
            let forget = super::memory_forget_tool(Arc::downgrade(&reopened));
            let replay = invoke(&forget, arguments).unwrap();
            assert_eq!(replay["retired"], receipt["retired"]);
            assert_eq!(brain_head(root.path()), inverse);
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(learned_rows(&reopened), rows);
        }
    }
}
