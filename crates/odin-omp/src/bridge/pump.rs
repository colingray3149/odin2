//! The child pump serializes writes, frame reads, and shutdown.

use super::*;

impl Shared {
    // Keep the process handle until its stop completes.
    async fn retire_process(
        self: &Arc<Self>,
        process: &mut Option<OmpProcess>,
    ) -> Result<(Vec<ObservedFrame>, Option<OmpExitRecord>), BridgeError> {
        let mut drained = Vec::new();
        let mut retained_bytes = 0usize;
        let Some(child) = process.as_mut() else {
            return Ok((drained, None));
        };
        if let Err(error) = child.close_stdin() {
            tracing::debug!("Closing harness stdin before stop failed: {error}");
        }
        let deadline = tokio::time::Instant::now() + self.process_spec.drain_timeout;
        let exit = loop {
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(budget, child.next_frame()).await {
                Ok(Ok(frame)) => {
                    let (observed, _immediate) = self.observe_decoded(frame).await?;
                    let next_bytes = retained_bytes.saturating_add(observed.raw_len());
                    let over_limit =
                        drained.len() >= DRAIN_FRAME_CAP || next_bytes > DRAIN_BYTE_CAP;
                    drained.push(observed);
                    if over_limit {
                        break Some(child.kill().await?);
                    }
                    retained_bytes = next_bytes;
                }
                Ok(Err(OmpProcessError::StdoutClosed { exit })) => {
                    if let Some(rejection) = exit.unfinished_sequence().cloned() {
                        drained.push(self.observe_rejected(rejection).await?);
                    }
                    break Some(*exit);
                }
                Ok(Err(OmpProcessError::FrameRejected(rejection))) => {
                    drained.push(self.observe_rejected(rejection).await?);
                    break Some(child.kill().await?);
                }
                Ok(Err(error)) => {
                    tracing::debug!("Draining harness before stop failed: {error}");
                    break Some(child.kill().await?);
                }
                Err(_) => break Some(child.kill().await?),
            }
        };
        *process = None;
        self.note_exit_record(exit.as_ref());
        Ok((drained, exit))
    }

    pub(super) async fn terminate_sequence(
        &self,
        process: &mut Option<OmpProcess>,
    ) -> Result<Option<OmpExitRecord>, BridgeError> {
        let result = match process.as_mut() {
            // Closing stdin preserves the remote job for the next harness attach.
            Some(child) if child.is_remote() => match child.graceful_stop().await {
                Ok(shutdown) => Ok(Some(shutdown.into_parts().1)),
                Err(error) => {
                    tracing::debug!("Stopping remote harness gracefully failed: {error}");
                    child.kill().await.map(Some).map_err(BridgeError::from)
                }
            },
            Some(child) => child.kill().await.map(Some).map_err(BridgeError::from),
            None => Ok(None),
        };
        if result.is_ok() {
            *process = None;
            if let Ok(exit) = &result {
                self.note_exit_record(exit.as_ref());
            }
        }
        let drained = self
            .drain_side_tasks(self.process_spec.kill_timeout.saturating_mul(2))
            .await;
        match (result, drained) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(exit), Ok(())) => Ok(exit),
        }
    }

    pub(super) async fn stop_sequence(
        self: &Arc<Self>,
        process: &mut Option<OmpProcess>,
        end_session: bool,
    ) -> Result<StopReport, BridgeError> {
        let retired = self.retire_process(process).await;
        let side = self
            .drain_side_tasks(self.process_spec.kill_timeout.saturating_mul(2))
            .await;
        let (drained, exit) = match retired {
            Ok(retired) => retired,
            Err(error) => return Err(error),
        };
        side?;
        // Daemon shutdown leaves the session available to reclaim; explicit close ends it.
        if end_session {
            if let Err(error) = self.finish_live_row(LiveSessionExit::Ended).await {
                tracing::error!(
                    "Recording the ended live session after harness stop failed: {error}"
                );
            }
        }
        Ok(StopReport {
            drained,
            exit,
            lease_released: false,
            incomplete: Vec::new(),
            children: Vec::new(),
        })
    }
}

/// Classifies every startup frame the process boundary retained — the ready
/// frame, any auxiliary frames interleaved inside the negotiation window, and
/// the negotiation response — in exact arrival order, without runtime
/// correlation. The single startup vocabulary shared by the pump's recording
/// path and any startup-evidence tooling.
pub(super) fn startup_observations(process: &OmpProcess) -> Vec<ObservedFrame> {
    process
        .startup_frames()
        .map(|frame| ObservedFrame::decoded(classify_frame(frame.value()), frame.clone(), None))
        .collect()
}

/// The dedicated pump: sole owner of the child process, interleaving bounded
/// outbound writes with frame reads, and classifying every frame.
pub(super) async fn pump_task(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<PumpMessage>,
    mut shutdown: watch::Receiver<bool>,
    initial: Option<OmpProcess>,
) -> Result<(), BridgeError> {
    let mut process = initial;
    let mut read_failed = false;
    let mut generation = shared.generation.load(Ordering::Acquire);
    // Startup frames are owned copies extracted before the first await, so
    // the pump never holds the single-owner process borrow across a
    // suspension point.
    let startup = process
        .as_ref()
        .map(startup_observations)
        .unwrap_or_default();
    if shared.record_process_startup(startup).await.is_err() {
        read_failed = true;
    }

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            },
            message = rx.recv() => {
                match message {
                    None => break,
                    Some(PumpMessage::Send {
                        generation: target_generation,
                        frame,
                        ack,
                    }) => {
                        if target_generation != generation {
                            let _ = ack.send(Err(BridgeError::ProcessDown {
                                detail: format!(
                                    "stale child generation {target_generation}; current generation is {generation}"
                                ),
                            }));
                            continue;
                        }
                        let result = match process.as_mut() {
                            Some(child) => child.send_json(&frame).await.map_err(Into::into),
                            None => Err(BridgeError::ProcessDown {
                                detail: "no live OMP child".to_owned(),
                            }),
                        };
                        if let Err(error) = &result {
                            shared.mark_failed(&format!("stdin write failed: {error}"))?;
                        }
                        let _ = ack.send(result);
                    }
                    Some(PumpMessage::SideResult {
                        generation: target_generation,
                        request_id,
                        kind,
                        result,
                        ack,
                    }) => {
                        let authorized = target_generation == generation
                            && shared.side_result_authorized(&request_id, kind)?;
                        let sent = if authorized {
                            let wire = side_result_frame(&request_id, kind, &result);
                            match process.as_mut() {
                                Some(child) => match child.send_json(&wire).await {
                                    Ok(()) => true,
                                    Err(error) => {
                                        read_failed = true;
                                        shared.close_side_admission()?;
                                        shared.mark_failed(&format!(
                                            "side-channel result write failed: {error}"
                                        ))?;
                                        false
                                    }
                                },
                                None => false,
                            }
                        } else {
                            false
                        };
                        let _ = ack.send(sent);
                    }
                    Some(PumpMessage::Install { process: next, ack }) => {
                        if process.is_some() {
                            let _ = ack.send(Err(BridgeError::ProcessDown {
                                detail: "recovery install refused while prior child authority remains"
                                    .to_owned(),
                            }));
                            continue;
                        }
                        let Some(next_generation) = generation.checked_add(1) else {
                            shared.mark_failed("OMP child generation exhausted")?;
                            let _ = ack.send(Err(BridgeError::ProcessDown {
                                detail: "OMP child generation exhausted".to_owned(),
                            }));
                            continue;
                        };
                        generation = next_generation;
                        shared.generation.store(generation, Ordering::Release);
                        process = Some(*next);
                        shared.note_process_exited(false);
                        read_failed = false;
                        let startup = shared
                            .record_process_startup(startup_observations(
                                process.as_ref().expect("installed child is present"),
                            ))
                            .await;
                        if startup.is_err() {
                            read_failed = true;
                            shared.close_side_admission()?;
                        }
                        let _ = ack.send(startup);
                    }
                    Some(PumpMessage::Terminate {
                        reason,
                        planned,
                        ack,
                    }) => {
                        shared.close_side_admission()?;
                        read_failed = true;
                        let result = shared.terminate_sequence(&mut process).await;
                        if result.is_ok() {
                            if let Some(next_generation) = generation.checked_add(1) {
                                generation = next_generation;
                                shared.generation.store(generation, Ordering::Release);
                            } else {
                                shared.mark_failed("OMP child generation exhausted")?;
                            }
                        }
                        // Only an UNPLANNED termination is a failure: a
                        // planned retirement (recovery/rollover respawn,
                        // probe crash injection) replaces the child on
                        // purpose and must never publish a Failed transition
                        // or a failure notice.
                        if !planned {
                            shared.mark_failed(&reason)?;
                        }
                        let _ = ack.send(result);
                    }
                    Some(PumpMessage::Stop {
                        end_session,
                        ack,
                    }) => {
                        shared.close_side_admission()?;
                        read_failed = true;
                        let report = shared.stop_sequence(&mut process, end_session).await;
                        shared_lock(&shared.correlation, "correlation")?
                            .fail_all(BridgeError::ProcessDown {
                                detail: "bridge stopping".to_owned(),
                            });
                        let _ = ack.send(report);
                    }
                }
            }
            read = async {
                process
                    .as_mut()
                    .expect("reader branch guarded by process.is_some()")
                    .next_frame()
                    .await
            }, if process.is_some() && !read_failed => {
                match read {
                    Ok(frame) => {
                        let (_observed, immediate) = shared.observe_decoded(frame).await?;
                        if let Some(reply) = immediate {
                            let sent = match process.as_mut() {
                                Some(child) => child.send_json(&reply).await,
                                None => Err(OmpProcessError::InvalidTransition {
                                    operation: "send_side_rejection",
                                    from: crate::process::OmpLifecycleState::Exited,
                                }),
                            };
                            if let Err(error) = sent {
                                read_failed = true;
                                shared.close_side_admission()?;
                                shared.mark_failed(&format!(
                                    "side-channel rejection write failed: {error}"
                                ))?;
                            }
                        }
                    }
                    Err(OmpProcessError::StdoutClosed { exit }) => {
                        if let Some(rejection) = exit.unfinished_sequence().cloned() {
                            shared.observe_rejected(rejection).await?;
                        }
                        read_failed = true;
                        shared.close_side_admission()?;
                        let binding = shared.binding_snapshot()?;
                        let how = match (exit.code(), exit.signal()) {
                            (Some(code), _) => format!("code={code}"),
                            (None, Some(signal)) => format!("signal={signal}"),
                            (None, None) => "status=unobserved".to_owned(),
                        };
                        tracing::info!(
                            "odind: session-runtime exited session={} seat={} {how}",
                            binding.session_id,
                            binding
                                .scope
                                .seat
                                .as_ref()
                                .map_or("", |seat| seat.as_str())
                        );
                        shared.mark_failed("OMP stdout closed; the child exited")?;
                        if exit.termination_proven() {
                            shared.note_process_exited(true);
                        }
                        // The child died outside any bridge-initiated stop:
                        // the durable row must leave `ready` truthfully.
                        shared.finish_live_row(LiveSessionExit::Failed).await?;
                    }
                    Err(OmpProcessError::FrameRejected(rejection)) => {
                        shared.observe_rejected(rejection).await?;
                        read_failed = true;
                        shared.close_side_admission()?;
                        shared.mark_failed("OMP frame rejected; the stream cannot resynchronize")?;
                    }
                    Err(error) => {
                        read_failed = true;
                        shared.close_side_admission()?;
                        shared.mark_failed(&format!("OMP read failed: {error}"))?;
                    }
                }
            }
        }
    }
    drop(process);
    Ok(())
}
