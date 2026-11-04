//! Model classes (`fast`, `standard`, `strong`): the owner declares each class's lanes in order
//! (dotfiles `gateway.classes`), and work that names a class runs on the first lane that
//! meets its needs and whose account has room left in its windows.

use serde::Serialize;

/// One lane of a class, as the router sees it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClassLane {
    pub lane: String,
    pub vision: bool,
    pub context_window: u64,
    /// Why the lane's account cannot take work now (a used-up window); `None` when it can.
    pub held: Option<String>,
}

/// What a request needs from its lane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Needs {
    pub vision: bool,
    pub context_tokens: u64,
}

impl ClassLane {
    /// Why this lane cannot take work with these needs; `None` when it can.
    pub fn refusal(&self, needs: Needs) -> Option<String> {
        if let Some(held) = &self.held {
            return Some(held.clone());
        }
        if needs.vision && !self.vision {
            return Some("cannot read images".to_owned());
        }
        (needs.context_tokens > self.context_window).then(|| {
            format!(
                "{}-token window is smaller than the {} tokens needed",
                self.context_window, needs.context_tokens
            )
        })
    }
}

/// The first lane in `order` that meets `needs`; the refusal names every lane and why it was passed over.
pub fn pick<'a>(
    class: &str,
    order: &'a [ClassLane],
    needs: Needs,
) -> Result<&'a ClassLane, String> {
    let mut passed = Vec::new();
    for lane in order {
        match lane.refusal(needs) {
            None => return Ok(lane),
            Some(reason) => passed.push(format!("{} ({reason})", lane.lane)),
        }
    }
    Err(format!(
        "class {class} has no lane that can take this work: {}",
        if passed.is_empty() {
            "it lists no lanes".to_owned()
        } else {
            passed.join(", ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(name: &str, vision: bool, held: Option<&str>) -> ClassLane {
        ClassLane {
            lane: name.to_owned(),
            vision,
            context_window: 500_000,
            held: held.map(str::to_owned),
        }
    }

    #[test]
    fn the_first_lane_with_room_and_the_needs_serves() {
        let order = [
            lane("goat-flash", false, Some("$14.00 of $14 per 5h used")),
            lane("grok", true, None),
            lane("astra", true, None),
        ];
        assert_eq!(pick("fast", &order, Needs::default()).unwrap().lane, "grok");
        let order = [lane("goat-flash", false, None), lane("grok", true, None)];
        assert_eq!(
            pick("fast", &order, Needs::default()).unwrap().lane,
            "goat-flash"
        );
        let photo = Needs {
            vision: true,
            context_tokens: 0,
        };
        assert_eq!(pick("fast", &order, photo).unwrap().lane, "grok");
        let error = pick("fast", &order[..1], photo).unwrap_err();
        assert_eq!(
            error,
            "class fast has no lane that can take this work: goat-flash (cannot read images)"
        );
    }
}
