//! odind runs with systemd's PrivateTmp, a directory under the host's /tmp.
//! If something removes that directory while odind runs, every temp file
//! odind or its sandboxes make fails (usage readers hold every lane, bwrap
//! cannot mount /tmp) and nothing recovers. The pump notices and stops odind
//! with the cause, so systemd restarts it with a fresh private /tmp.

use std::time::Duration as StdDuration;

const POLL: StdDuration = StdDuration::from_secs(60);

pub(super) fn arm_private_tmp_pump(pumps: &mut tokio::task::JoinSet<Result<(), String>>) {
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(POLL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let probe = tokio::task::spawn_blocking(tempfile::tempfile)
                .await
                .map_err(|error| format!("private /tmp probe panicked: {error}"))?;
            if let Err(error) = probe {
                return Err(format!(
                    "odind's /tmp ({}) no longer accepts files ({error}); \
                     its private directory was removed, so odind stops for a fresh one",
                    std::env::temp_dir().display()
                ));
            }
        }
    });
}
