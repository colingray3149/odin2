//!
//! Text and key names as Linux keycodes on niri's US layout (the seat's
//! keymap applies to the virtual keyboard like any other).

use evdev::KeyCode;

/// The key and whether Shift is held for one typed character.
pub(crate) fn char_key(character: char) -> Option<(KeyCode, bool)> {
    const LETTERS: [KeyCode; 26] = [
        KeyCode::KEY_A,
        KeyCode::KEY_B,
        KeyCode::KEY_C,
        KeyCode::KEY_D,
        KeyCode::KEY_E,
        KeyCode::KEY_F,
        KeyCode::KEY_G,
        KeyCode::KEY_H,
        KeyCode::KEY_I,
        KeyCode::KEY_J,
        KeyCode::KEY_K,
        KeyCode::KEY_L,
        KeyCode::KEY_M,
        KeyCode::KEY_N,
        KeyCode::KEY_O,
        KeyCode::KEY_P,
        KeyCode::KEY_Q,
        KeyCode::KEY_R,
        KeyCode::KEY_S,
        KeyCode::KEY_T,
        KeyCode::KEY_U,
        KeyCode::KEY_V,
        KeyCode::KEY_W,
        KeyCode::KEY_X,
        KeyCode::KEY_Y,
        KeyCode::KEY_Z,
    ];
    const DIGITS: [KeyCode; 10] = [
        KeyCode::KEY_0,
        KeyCode::KEY_1,
        KeyCode::KEY_2,
        KeyCode::KEY_3,
        KeyCode::KEY_4,
        KeyCode::KEY_5,
        KeyCode::KEY_6,
        KeyCode::KEY_7,
        KeyCode::KEY_8,
        KeyCode::KEY_9,
    ];
    let plain = |key| Some((key, false));
    let shifted = |key| Some((key, true));
    match character {
        'a'..='z' => plain(LETTERS[character as usize - 'a' as usize]),
        'A'..='Z' => shifted(LETTERS[character as usize - 'A' as usize]),
        '0'..='9' => plain(DIGITS[character as usize - '0' as usize]),
        ' ' => plain(KeyCode::KEY_SPACE),
        '\n' => plain(KeyCode::KEY_ENTER),
        '\t' => plain(KeyCode::KEY_TAB),
        '-' => plain(KeyCode::KEY_MINUS),
        '=' => plain(KeyCode::KEY_EQUAL),
        '[' => plain(KeyCode::KEY_LEFTBRACE),
        ']' => plain(KeyCode::KEY_RIGHTBRACE),
        '\\' => plain(KeyCode::KEY_BACKSLASH),
        ';' => plain(KeyCode::KEY_SEMICOLON),
        '\'' => plain(KeyCode::KEY_APOSTROPHE),
        '`' => plain(KeyCode::KEY_GRAVE),
        ',' => plain(KeyCode::KEY_COMMA),
        '.' => plain(KeyCode::KEY_DOT),
        '/' => plain(KeyCode::KEY_SLASH),
        '!' => shifted(KeyCode::KEY_1),
        '@' => shifted(KeyCode::KEY_2),
        '#' => shifted(KeyCode::KEY_3),
        '$' => shifted(KeyCode::KEY_4),
        '%' => shifted(KeyCode::KEY_5),
        '^' => shifted(KeyCode::KEY_6),
        '&' => shifted(KeyCode::KEY_7),
        '*' => shifted(KeyCode::KEY_8),
        '(' => shifted(KeyCode::KEY_9),
        ')' => shifted(KeyCode::KEY_0),
        '_' => shifted(KeyCode::KEY_MINUS),
        '+' => shifted(KeyCode::KEY_EQUAL),
        '{' => shifted(KeyCode::KEY_LEFTBRACE),
        '}' => shifted(KeyCode::KEY_RIGHTBRACE),
        '|' => shifted(KeyCode::KEY_BACKSLASH),
        ':' => shifted(KeyCode::KEY_SEMICOLON),
        '"' => shifted(KeyCode::KEY_APOSTROPHE),
        '~' => shifted(KeyCode::KEY_GRAVE),
        '<' => shifted(KeyCode::KEY_COMMA),
        '>' => shifted(KeyCode::KEY_DOT),
        '?' => shifted(KeyCode::KEY_SLASH),
        _ => None,
    }
}

/// One chord such as `ctrl+shift+t` or `Return`: modifiers, then the key.
#[derive(Debug, PartialEq)]
pub(crate) struct Chord {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    pub super_key: bool,
    pub key: KeyCode,
}

impl Chord {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut chord = Chord {
            ctrl: false,
            shift: false,
            alt: false,
            super_key: false,
            key: KeyCode::KEY_RESERVED,
        };
        let parts: Vec<&str> = text.split('+').collect();
        let (last, modifiers) = parts
            .split_last()
            .filter(|(last, _)| !last.is_empty())
            .ok_or_else(|| format!("{text:?} names no key"))?;
        for modifier in modifiers {
            match modifier.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => chord.ctrl = true,
                "shift" => chord.shift = true,
                "alt" => chord.alt = true,
                "super" | "mod" | "meta" | "win" => chord.super_key = true,
                other => {
                    return Err(format!(
                        "{other:?} in {text:?} is not ctrl, shift, alt or super"
                    ))
                }
            }
        }
        let (key, shift) =
            named_key(last).ok_or_else(|| format!("{last:?} in {text:?} is not a key name"))?;
        chord.key = key;
        chord.shift |= shift;
        Ok(chord)
    }
}

/// The key a name stands for and whether it needs Shift: `?` is Shift+/.
/// Letters are case-insensitive; Shift is only ever written as a modifier.
fn named_key(name: &str) -> Option<(KeyCode, bool)> {
    let mut characters = name.chars();
    if let (Some(character), None) = (characters.next(), characters.next()) {
        let (key, shift) = char_key(character)?;
        return Some((key, shift && !character.is_ascii_uppercase()));
    }
    let lower = name.to_ascii_lowercase();
    if let Some(number) = lower.strip_prefix('f').and_then(|n| n.parse::<u16>().ok()) {
        const F: [KeyCode; 12] = [
            KeyCode::KEY_F1,
            KeyCode::KEY_F2,
            KeyCode::KEY_F3,
            KeyCode::KEY_F4,
            KeyCode::KEY_F5,
            KeyCode::KEY_F6,
            KeyCode::KEY_F7,
            KeyCode::KEY_F8,
            KeyCode::KEY_F9,
            KeyCode::KEY_F10,
            KeyCode::KEY_F11,
            KeyCode::KEY_F12,
        ];
        return F
            .get(usize::from(number).checked_sub(1)?)
            .map(|key| (*key, false));
    }
    let key = match lower.as_str() {
        "enter" | "return" => KeyCode::KEY_ENTER,
        "tab" => KeyCode::KEY_TAB,
        "esc" | "escape" => KeyCode::KEY_ESC,
        "backspace" => KeyCode::KEY_BACKSPACE,
        "delete" | "del" => KeyCode::KEY_DELETE,
        "insert" => KeyCode::KEY_INSERT,
        "home" => KeyCode::KEY_HOME,
        "end" => KeyCode::KEY_END,
        "pageup" | "pgup" => KeyCode::KEY_PAGEUP,
        "pagedown" | "pgdn" => KeyCode::KEY_PAGEDOWN,
        "up" => KeyCode::KEY_UP,
        "down" => KeyCode::KEY_DOWN,
        "left" => KeyCode::KEY_LEFT,
        "right" => KeyCode::KEY_RIGHT,
        "space" => KeyCode::KEY_SPACE,
        "print" => KeyCode::KEY_SYSRQ,
        "menu" => KeyCode::KEY_COMPOSE,
        "minus" => KeyCode::KEY_MINUS,
        "plus" | "equal" => KeyCode::KEY_EQUAL,
        _ => return None,
    };
    Some((key, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chords_and_text_map_to_us_keys() {
        assert_eq!(char_key('Q'), Some((KeyCode::KEY_Q, true)));
        assert_eq!(char_key('?'), Some((KeyCode::KEY_SLASH, true)));
        assert_eq!(char_key('é'), None);
        let chord = Chord::parse("ctrl+shift+T").unwrap();
        assert!(chord.ctrl && chord.shift && !chord.alt && chord.key == KeyCode::KEY_T);
        assert_eq!(Chord::parse("Return").unwrap().key, KeyCode::KEY_ENTER);
        assert_eq!(Chord::parse("F11").unwrap().key, KeyCode::KEY_F11);
        assert!(Chord::parse("hyper+a").unwrap_err().contains("not ctrl"));
        assert!(Chord::parse("ctrl+").is_err());
    }
}
