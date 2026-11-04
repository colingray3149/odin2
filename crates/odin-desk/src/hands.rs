//!
//! The uinput pointer and keyboard. The pointer is absolute: niri maps an
//! absolute device with no output of its own across the bounding box of all
//! outputs, so one range covers every monitor without pointer acceleration.

use std::time::Duration;

use evdev::uinput::VirtualDevice;
use evdev::{
    AbsInfo, AbsoluteAxisCode, AbsoluteAxisEvent, AttributeSet, InputEvent, KeyCode, KeyEvent,
    RelativeAxisCode, RelativeAxisEvent, UinputAbsSetup,
};

use crate::keys::{char_key, Chord};
use crate::niri::Rect;

/// Absolute range: one step is under a tenth of a pixel across 4480 px.
const RANGE: i32 = 65_535;
/// How long libinput needs to open a new virtual device; events sent sooner are lost.
const DEVICE_READY: Duration = Duration::from_millis(400);
/// Between keystrokes: fast, and slow enough for every client to keep up.
const KEY_GAP: Duration = Duration::from_millis(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Button {
    Left,
    Right,
    Middle,
}

/// The device value for desktop coordinate `value` on an axis that starts at
/// `origin` and spans `size`, clamped to the device range.
fn absolute(value: f64, origin: f64, size: f64) -> i32 {
    (((value - origin) / size) * f64::from(RANGE + 1)).clamp(0.0, f64::from(RANGE)) as i32
}

pub(crate) struct Hands {
    pointer: VirtualDevice,
    keyboard: VirtualDevice,
}

impl Hands {
    pub(crate) fn new() -> Result<Self, String> {
        let failed = |what: &str, error: std::io::Error| {
            format!(
                "the uinput {what} could not be created ({error}); /dev/uinput needs rw for the desktop user"
            )
        };
        let axis = |code| UinputAbsSetup::new(code, AbsInfo::new(0, 0, RANGE, 0, 0, 1));
        let mut buttons = AttributeSet::<KeyCode>::new();
        for button in [KeyCode::BTN_LEFT, KeyCode::BTN_RIGHT, KeyCode::BTN_MIDDLE] {
            buttons.insert(button);
        }
        let mut wheels = AttributeSet::<RelativeAxisCode>::new();
        wheels.insert(RelativeAxisCode::REL_WHEEL);
        wheels.insert(RelativeAxisCode::REL_HWHEEL);
        let pointer = VirtualDevice::builder()
            .and_then(|builder| {
                builder
                    .name("odin-desk pointer")
                    .with_keys(&buttons)?
                    .with_absolute_axis(&axis(AbsoluteAxisCode::ABS_X))?
                    .with_absolute_axis(&axis(AbsoluteAxisCode::ABS_Y))?
                    .with_relative_axes(&wheels)?
                    .build()
            })
            .map_err(|error| failed("pointer", error))?;
        let mut keys = AttributeSet::<KeyCode>::new();
        for code in 1..=248 {
            keys.insert(KeyCode::new(code));
        }
        let keyboard = VirtualDevice::builder()
            .and_then(|builder| builder.name("odin-desk keyboard").with_keys(&keys)?.build())
            .map_err(|error| failed("keyboard", error))?;
        std::thread::sleep(DEVICE_READY);
        Ok(Self { pointer, keyboard })
    }

    /// Moves the pointer to the desktop point (x, y) in logical pixels.
    pub(crate) fn point(&mut self, desk: Rect, x: f64, y: f64) -> Result<(), String> {
        self.pointer
            .emit(&[
                *AbsoluteAxisEvent::new(AbsoluteAxisCode::ABS_X, absolute(x, desk.x, desk.w)),
                *AbsoluteAxisEvent::new(AbsoluteAxisCode::ABS_Y, absolute(y, desk.y, desk.h)),
            ])
            .map_err(|error| format!("moving the pointer failed: {error}"))
    }

    pub(crate) fn button(&mut self, button: Button, down: bool) -> Result<(), String> {
        let code = match button {
            Button::Left => KeyCode::BTN_LEFT,
            Button::Right => KeyCode::BTN_RIGHT,
            Button::Middle => KeyCode::BTN_MIDDLE,
        };
        self.pointer
            .emit(&[*KeyEvent::new(code, i32::from(down))])
            .map_err(|error| format!("the {button:?} button failed: {error}"))
    }

    /// Wheel clicks: positive `down` scrolls down, positive `right` right.
    pub(crate) fn scroll(&mut self, down: i32, right: i32) -> Result<(), String> {
        let mut events = Vec::new();
        if down != 0 {
            events.push(*RelativeAxisEvent::new(RelativeAxisCode::REL_WHEEL, -down));
        }
        if right != 0 {
            events.push(*RelativeAxisEvent::new(RelativeAxisCode::REL_HWHEEL, right));
        }
        self.pointer
            .emit(&events)
            .map_err(|error| format!("scrolling failed: {error}"))
    }

    fn keys(&mut self, events: &[InputEvent]) -> Result<(), String> {
        self.keyboard
            .emit(events)
            .map_err(|error| format!("the keyboard failed: {error}"))
    }

    /// Types ASCII text; `keep_going` is asked before every character so a
    /// stop lands mid-text.
    pub(crate) fn type_text(
        &mut self,
        text: &str,
        keep_going: &dyn Fn() -> Result<(), String>,
    ) -> Result<(), String> {
        for character in text.chars() {
            keep_going()?;
            let (key, shift) = char_key(character)
                .ok_or_else(|| format!("{character:?} has no key on the US layout"))?;
            let press = |down| *KeyEvent::new(key, down);
            let shift_key = |down| *KeyEvent::new(KeyCode::KEY_LEFTSHIFT, down);
            if shift {
                self.keys(&[shift_key(1), press(1)])?;
                self.keys(&[press(0), shift_key(0)])?;
            } else {
                self.keys(&[press(1)])?;
                self.keys(&[press(0)])?;
            }
            std::thread::sleep(KEY_GAP);
        }
        Ok(())
    }

    pub(crate) fn chord(&mut self, chord: &Chord) -> Result<(), String> {
        let modifiers: Vec<KeyCode> = [
            (chord.ctrl, KeyCode::KEY_LEFTCTRL),
            (chord.shift, KeyCode::KEY_LEFTSHIFT),
            (chord.alt, KeyCode::KEY_LEFTALT),
            (chord.super_key, KeyCode::KEY_LEFTMETA),
        ]
        .into_iter()
        .filter_map(|(held, key)| held.then_some(key))
        .collect();
        let mut down: Vec<InputEvent> = modifiers
            .iter()
            .map(|key| *KeyEvent::new(*key, 1))
            .collect();
        down.push(*KeyEvent::new(chord.key, 1));
        self.keys(&down)?;
        let mut up = vec![*KeyEvent::new(chord.key, 0)];
        up.extend(modifiers.iter().rev().map(|key| *KeyEvent::new(*key, 0)));
        self.keys(&up)?;
        std::thread::sleep(KEY_GAP);
        Ok(())
    }
}
