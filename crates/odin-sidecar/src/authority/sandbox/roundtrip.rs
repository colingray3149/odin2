//! Include cleanup failures in the effector result so a reply cannot hide unfinished work.

use odin_kernel::stop::{
    mint_worker_id, CommandSpec, EnvironmentBuilder, FrozenArgv, RegisteredServiceBinding,
    ScopeLifetime, ScopeLimits, WorkerNaming, CORRELATION_ENV,
};
use odin_kernel::{ExecutorFault, StopHandle, PARENT_AUTHORITY_ENV};
use odin_sidecar_protocol::{
    read_effect_response, write_effect_request, EffectBehavior, EffectOp, EffectRequest,
    EffectResponse, EFFECTOR_BWRAP_ENV, EFFECTOR_CACHE_ROOT_ENV, EFFECTOR_CARGO_GIT_CACHE_ENV,
    EFFECTOR_CARGO_REGISTRY_CACHE_ENV, EFFECTOR_CONTEXT_ROOT_ENV, EFFECTOR_NIX_CONFIG_ROOT_ENV,
    EFFECTOR_TOOL_PATH_ENV,
};
use odin_types::CorrelationId;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::broker::RoundTripBroker;
use super::stop::{in_flight_identity, retire_effector, EffectReaders};
use super::{
    require_string, strict_field, EffectorExecutor, EFFECTOR_TX_ID, EFFECTOR_WP_ID, EFFECT_POLL,
};

impl EffectorExecutor {
    /// Every exit path stops the worker and broker while preserving durable worker ledgers.
    pub(super) fn round_trip(
        &self,
        request: EffectRequest,
        stop: Option<&Arc<StopHandle>>,
        deadline_ms: u64,
    ) -> Result<EffectResponse, ExecutorFault> {
        if let Some(fault) = expired_before_dispatch(deadline_ms, (self.clock)()) {
            return Err(fault);
        }
        let broker = match self.channel.as_ref() {
            None => None,
            Some(channel) => Some(RoundTripBroker::open(self, channel, &request)?),
        };
        let mut readers = EffectReaders::default();
        let result =
            self.dispatch_round_trip(&request, stop, deadline_ms, broker.as_ref(), &mut readers);
        let result = match broker {
            None => result,
            Some(broker) => combine_with_cleanup(result, broker.dispose()),
        };
        let mut response = combine_with_cleanup(result, readers.join())?;
        response.worker_stopped = Some(response.worker_stopped.unwrap_or(true));
        Ok(response)
    }

    fn dispatch_round_trip(
        &self,
        request: &EffectRequest,
        stop: Option<&Arc<StopHandle>>,
        deadline_ms: u64,
        broker: Option<&RoundTripBroker>,
        readers: &mut EffectReaders,
    ) -> Result<EffectResponse, ExecutorFault> {
        let op = match request.op() {
            EffectOp::Declare => "declare",
            EffectOp::Observe => "observe",
            EffectOp::Execute => "execute",
        };
        let mut request_bytes = Vec::new();
        write_effect_request(&mut request_bytes, request, self.request_ceiling).map_err(
            |error| ExecutorFault::Rejected {
                detail: format!("effect request could not be delivered: {error}"),
            },
        )?;

        let stop_auth = self.stop_authority()?;
        let worker_id = mint_worker_id().map_err(|error| ExecutorFault::Rejected {
            detail: format!("could not mint effector WorkerId: {error}"),
        })?;
        let correlation =
            CorrelationId::new(worker_id.as_str()).map_err(|error| ExecutorFault::Rejected {
                detail: format!("could not bind effector correlation: {error}"),
            })?;
        let argv = FrozenArgv::new(
            [self.program.clone().into_os_string(), OsString::from(op)],
            8,
            8 * 1024,
        )
        .map_err(|error| ExecutorFault::Rejected {
            detail: format!("compiled effector argv rejected: {error}"),
        })?;
        // Build the environment from host configuration, never arbitrary request fields.
        let mut sandbox_environment: Vec<(&'static str, String)> = Vec::new();
        {
            let sandbox = self
                .sandbox
                .as_ref()
                .ok_or_else(|| ExecutorFault::Rejected {
                    detail: "effector filesystem sandbox binding is absent".to_owned(),
                })?;
            let mut push_path = |name: &'static str, path: &Path| {
                let value = path.to_str().ok_or_else(|| ExecutorFault::Rejected {
                    detail: format!("sandbox path {} is not UTF-8", path.display()),
                })?;
                sandbox_environment.push((name, value.to_owned()));
                Ok::<(), ExecutorFault>(())
            };
            push_path(EFFECTOR_BWRAP_ENV, &sandbox.bwrap)?;
            push_path(EFFECTOR_CACHE_ROOT_ENV, &sandbox.cache_root)?;
            if let Some(path) = &sandbox.context_root {
                push_path(EFFECTOR_CONTEXT_ROOT_ENV, path)?;
            }
            if let Some(path) = &sandbox.cargo_registry_cache {
                push_path(EFFECTOR_CARGO_REGISTRY_CACHE_ENV, path)?;
            }
            if let Some(path) = &sandbox.cargo_git_cache {
                push_path(EFFECTOR_CARGO_GIT_CACHE_ENV, path)?;
            }
            if let Some(path) = &sandbox.nix_config_root {
                push_path(EFFECTOR_NIX_CONFIG_ROOT_ENV, path)?;
            }
            sandbox_environment.push((EFFECTOR_TOOL_PATH_ENV, sandbox.tool_path.clone()));
        }
        let mut environment_keys = vec![CORRELATION_ENV];
        if broker.is_some() {
            environment_keys.push(PARENT_AUTHORITY_ENV);
        }
        environment_keys.extend(sandbox_environment.iter().map(|(name, _)| *name));
        let mut environment = EnvironmentBuilder::new(environment_keys)
            .map_err(|error| ExecutorFault::Rejected {
                detail: format!("effector environment rejected: {error}"),
            })?
            .set(CORRELATION_ENV, correlation.as_str())
            .map_err(|error| ExecutorFault::Rejected {
                detail: format!("effector correlation environment rejected: {error}"),
            })?;
        if let Some(broker) = broker {
            environment = environment
                .set(PARENT_AUTHORITY_ENV, broker.prepare(&worker_id)?)
                .map_err(|error| ExecutorFault::Rejected {
                    detail: format!("effector parent descriptor environment rejected: {error}"),
                })?;
        }
        for (name, value) in &sandbox_environment {
            environment =
                environment
                    .set(name, value)
                    .map_err(|error| ExecutorFault::Rejected {
                        detail: format!("effector sandbox environment rejected: {error}"),
                    })?;
        }
        let environment = environment.build();
        let current_dir = std::env::current_dir().map_err(|error| ExecutorFault::Rejected {
            detail: format!("effector current_dir is unavailable: {error}"),
        })?;
        if !current_dir.is_absolute() {
            return Err(ExecutorFault::Rejected {
                detail: "effector current_dir must be absolute".to_owned(),
            });
        }
        let spec = CommandSpec {
            argv,
            environment,
            current_dir,
        };
        let binding =
            RegisteredServiceBinding::new(self.program.clone(), self.binding_digest.clone())
                .map_err(|error| ExecutorFault::Rejected {
                    detail: format!(
                        "compiled effector {:?} could not start: {error}",
                        self.program.display()
                    ),
                })?;
        let naming = WorkerNaming::new(EFFECTOR_TX_ID, EFFECTOR_WP_ID, 1, worker_id.clone())
            .map_err(|error| ExecutorFault::Rejected {
                detail: format!("effector worker naming rejected: {error}"),
            })?;
        let now_ms = (self.clock)();
        if let Some(fault) = expired_before_dispatch(deadline_ms, now_ms) {
            return Err(fault);
        }
        // Startup consumes the same deadline as execution.
        let remaining_ms = deadline_ms - now_ms;
        let limits = ScopeLimits {
            lifetime: ScopeLifetime::Bounded(Duration::from_millis(remaining_ms)),
            timeout_stop: Duration::from_secs(2),
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        };
        let launch = stop_auth
            .launch_registered_service(naming, &correlation, &spec, limits, &binding)
            .map_err(|error| ExecutorFault::Rejected {
                detail: format!(
                    "compiled effector {:?} could not start: {error}",
                    self.program.display()
                ),
            })?;
        // Publish the worker identity so a concurrent stop can report the running helper.
        if let Some(stop_handle) = stop {
            if let Some(identity) = in_flight_identity(&launch.identity) {
                stop_handle.register_process(identity);
            }
        }
        // Activate only for the launched identity so another process cannot use the descriptor.
        let result = (|| {
            if let Some(broker) = broker {
                if let Err(error) = broker.activate(&worker_id, &launch.identity) {
                    return Err(ExecutorFault::Rejected {
                        detail: format!("parent scope activation failed: {error}"),
                    });
                }
            }
            // Startup can exhaust the deadline before any request is sent.
            if let Some(fault) = expired_before_dispatch(deadline_ms, (self.clock)()) {
                return Err(fault);
            }
            if let Err(error) = stop_auth.write_worker_stdin(&worker_id, &request_bytes) {
                return Err(ExecutorFault::Uncertain {
                    detail: format!("effect request could not be delivered: {error}"),
                });
            }

            let stdout = readers.stoppable(launch.stdout);
            let stderr = readers.stoppable(launch.stderr);
            let stderr_ceiling = self.response_ceiling.min(65_536);
            readers.stderr = Some(std::thread::spawn(move || {
                let mut sink = Vec::with_capacity(stderr_ceiling.min(8_192));
                let _ = stderr
                    .take(stderr_ceiling.saturating_add(1) as u64)
                    .read_to_end(&mut sink);
            }));
            let (sender, receiver) = std::sync::mpsc::channel();
            let ceiling = self.response_ceiling;
            readers.stdout = Some(std::thread::spawn(move || {
                let mut stdout = stdout;
                let result = read_effect_response(&mut stdout, ceiling)
                    .map_err(|error| ExecutorFault::Uncertain {
                        detail: format!("compiled effector response failed: {error}"),
                    })
                    .and_then(|response| {
                        response.ok_or_else(|| ExecutorFault::Uncertain {
                            detail: "compiled effector closed without a response".to_owned(),
                        })
                    });
                let _ = sender.send(result);
            }));
            let mut stdin_open = true;
            loop {
                match receiver.recv_timeout(EFFECT_POLL) {
                    Ok(Ok(response)) => return Ok(response),
                    Ok(Err(fault)) => {
                        return Err(fault);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(ExecutorFault::Uncertain {
                            detail: "effector response reader exited unexpectedly".to_owned(),
                        });
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
                if stop.is_some_and(|stop| stop.is_cancelled()) && stdin_open {
                    // Stdin EOF asks the effector to stop its children before StopAuthority containment.
                    let _ = stop_auth.close_worker_stdin(&worker_id);
                    stdin_open = false;
                }
                if (self.clock)() >= deadline_ms {
                    return Err(ExecutorFault::Uncertain {
                        detail: "compiled effector did not answer before the effect deadline"
                            .to_owned(),
                    });
                }
            }
        })();
        combine_with_cleanup(result, retire_effector(stop_auth, &worker_id))
    }

    /// Admit only configured Git and the requested interpreter or executable; later RPCs cannot add programs.
    pub(super) fn round_trip_catalog(
        &self,
        request: &EffectRequest,
    ) -> Result<odin_kernel::AllowedParentBindings, ExecutorFault> {
        let sandbox = self
            .sandbox
            .as_ref()
            .ok_or_else(|| ExecutorFault::Rejected {
                detail: "effector filesystem sandbox binding is absent".to_owned(),
            })?;
        let mut programs = vec![PathBuf::from(&self.capsule.git_bin), sandbox.bwrap.clone()];
        if matches!(request, EffectRequest::Execute { .. }) {
            match request.behavior() {
                EffectBehavior::Eval => {
                    let binding =
                        self.interpreters
                            .as_ref()
                            .ok_or_else(|| ExecutorFault::Rejected {
                                detail: "eval interpreter binding is absent; no interpreter may be "
                                    .to_owned()
                                    + "admitted to the round-trip catalog",
                            })?;
                    let interpreter = Self::request_field(request, "interpreter")?;
                    let program =
                        binding
                            .program(&interpreter)
                            .ok_or_else(|| ExecutorFault::Rejected {
                                detail: format!(
                            "eval interpreter {interpreter:?} is outside the closed python|bun enum"
                        ),
                            })?;
                    programs.push(program.to_path_buf());
                }
                EffectBehavior::Execute => {
                    if let Some(program) = Self::execute_payload_program(request)? {
                        programs.push(program);
                    }
                }
                _ => {}
            }
        }
        let mut admitted = BTreeSet::new();
        let mut bindings = Vec::new();
        for program in programs {
            if admitted.insert(program.clone()) {
                bindings.push(catalog_binding(&program)?);
            }
        }
        odin_kernel::AllowedParentBindings::new(bindings).map_err(|error| ExecutorFault::Rejected {
            detail: format!("round-trip parent catalog rejected: {error}"),
        })
    }

    fn request_field(request: &EffectRequest, field: &str) -> Result<String, ExecutorFault> {
        let arguments = match request {
            EffectRequest::Declare { arguments, .. }
            | EffectRequest::Observe { arguments, .. }
            | EffectRequest::Execute { arguments, .. } => arguments,
        };
        require_string(arguments, field)
    }

    fn execute_payload_program(request: &EffectRequest) -> Result<Option<PathBuf>, ExecutorFault> {
        if request.behavior() != EffectBehavior::Execute {
            return Ok(None);
        }
        let arguments = match request {
            EffectRequest::Declare { arguments, .. }
            | EffectRequest::Observe { arguments, .. }
            | EffectRequest::Execute { arguments, .. } => arguments,
        };
        let argv = strict_field(arguments, "argv")?;
        let odin_strict_json::Value::Array(items) = argv else {
            return Err(ExecutorFault::Rejected {
                detail: "execute payload argv must be a strict array".to_owned(),
            });
        };
        let Some(odin_strict_json::Value::String(program)) = items.first() else {
            return Err(ExecutorFault::Rejected {
                detail: "execute payload argv must begin with one exact program string".to_owned(),
            });
        };
        if program.is_empty() {
            return Err(ExecutorFault::Rejected {
                detail: "execute payload argv[0] is empty".to_owned(),
            });
        }
        Ok(Some(PathBuf::from(program)))
    }
}

/// Pre-send expiry is a known refusal; expiry after sending remains uncertain.
fn expired_before_dispatch(deadline_ms: u64, now_ms: u64) -> Option<ExecutorFault> {
    (now_ms >= deadline_ms).then(|| ExecutorFault::Rejected {
        detail: format!(
            "effect deadline already exhausted before dispatch: no effect request was \
             sent and nothing landed (deadline {deadline_ms}ms, now {now_ms}ms)"
        ),
    })
}

/// Cleanup failure makes a successful exchange uncertain and is retained alongside an exchange failure.
fn combine_with_cleanup<T>(
    result: Result<T, ExecutorFault>,
    cleanup: Result<(), String>,
) -> Result<T, ExecutorFault> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(cleanup)) => Err(ExecutorFault::Uncertain {
            detail: format!("round trip answered but broker cleanup failed: {cleanup}"),
        }),
        (Err(fault), Err(cleanup)) => Err(match fault {
            ExecutorFault::Rejected { detail } => ExecutorFault::Rejected {
                detail: format!("{detail}; broker cleanup failed: {cleanup}"),
            },
            ExecutorFault::Uncertain { detail } => ExecutorFault::Uncertain {
                detail: format!("{detail}; broker cleanup failed: {cleanup}"),
            },
            landed => landed,
        }),
    }
}

/// Hash executable bytes incrementally so large programs need not be loaded into memory.
fn catalog_binding(
    executable: &Path,
) -> Result<odin_kernel::ParentExecutableBinding, ExecutorFault> {
    let digest = blake3_file_digest(executable)?;
    odin_kernel::ParentExecutableBinding::isolated(executable.to_path_buf(), digest).map_err(
        |error| ExecutorFault::Rejected {
            detail: format!(
                "catalog executable {} is not admittable: {error}",
                executable.display()
            ),
        },
    )
}

fn blake3_file_digest(path: &Path) -> Result<String, ExecutorFault> {
    let mut file = std::fs::File::open(path).map_err(|error| ExecutorFault::Rejected {
        detail: format!(
            "catalog executable {} is unreadable: {error}",
            path.display()
        ),
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ExecutorFault::Rejected {
                detail: format!(
                    "catalog executable {} is unreadable: {error}",
                    path.display()
                ),
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
