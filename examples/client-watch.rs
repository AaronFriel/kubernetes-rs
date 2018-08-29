#![feature(uniform_paths)]
#![feature(try_blocks, try_trait, type_ascription)]

use failure::{Error, Fail};
use futures::{prelude::*, stream::Stream};
use hyper::rt;
use k8s_openapi::v1_11::{
    api::core::v1::*,
    apimachinery::pkg::{apis::meta::v1::*, runtime::*},
};
use log::{error, info};
use std::{option::NoneError, result::Result};

use keel::client::{Client, KubernetesError, Observed, RequestOpts};

type OptionResult<T> = Result<T, NoneError>;

fn opt_or<T>(opt: OptionResult<T>, optb: T) -> T {
    opt.unwrap_or(optb)
}

#[derive(Fail, Debug)]
#[fail(display = "Parse error {}", reason)]
struct ParseError {
    reason: String,
}

fn pod_name(p: &Pod) -> &str {
    opt_or(
        try { p.metadata.as_ref()?.name.as_ref()?.as_str() },
        "(no name)",
    )
}

fn print_pod_state(p: &Pod) {
    let name = pod_name(p);
    let status = opt_or(
        try { p.status.as_ref()?.phase.as_ref()?.as_str() },
        "Unknown",
    );

    println!("pod {} - {}", name, status);

    let empty_vec = Vec::new();
    let init_statuses = opt_or(
        try { p.status.as_ref()?.init_container_statuses.as_ref()? },
        &empty_vec,
    );
    let container_statuses = opt_or(
        try { p.status.as_ref()?.container_statuses.as_ref()? },
        &empty_vec,
    );

    for c in init_statuses.iter().chain(container_statuses.iter()) {
        print!("  -> {}: ", c.name);
        if let Some(state) = &c.state {
            if let Some(waiting) = &state.waiting {
                println!(
                    "waiting: {}",
                    waiting
                        .message
                        .as_ref()
                        .or_else(|| waiting.reason.as_ref())
                        .map(String::as_str)
                        .unwrap_or("waiting")
                )
            } else if let Some(running) = &state.running {
                match running.started_at {
                    Some(Time(t)) => println!("running since {}", t),
                    None => println!("running"),
                }
            } else if let Some(s) = &state.terminated {
                if let Some(msg) = &s.message {
                    println!("terminated: {}", msg)
                } else if let Some(Time(t)) = &s.finished_at {
                    println!("exited with code {} at {}", s.exit_code, t)
                } else {
                    println!("exited with code {}", s.exit_code)
                }
            } else {
                println!("state unknown")
            }
        } else {
            println!("state unknown")
        };
    }
}

fn handle_pod_event(event: WatchEvent) -> Result<(), Error> {
    match event.type_.to_ascii_lowercase().as_str() {
        "added" | "modified" => {
            let RawExtension(object) = event.object;
            let p: Pod = serde_json::from_value(object)?;
            print_pod_state(&p);
        }
        "deleted" => {
            let RawExtension(object) = event.object;
            let p: Pod = serde_json::from_value(object)?;
            println!("deleted {}", pod_name(&p));
        }
        other => {
            let RawExtension(object) = event.object;
            match (try { object.get("metadata")?.get("resource_version")?.to_string() }) {
                Ok(_version) => {
                    info!("Ignoring {} event {:#?}", other, object);
                }
                Err(NoneError) => {
                    let status_message: Result<String, Error> = try {
                        let s: Status = serde_json::from_value(object)?;
                        format!(
                            "status {}-{}, reason: {}, message: {}",
                            s.code.unwrap_or(-1),
                            opt_or(try { s.status?.as_str() }, "(unknown)"),
                            opt_or(try { s.reason?.as_str() }, "(unknown)"),
                            opt_or(try { s.message?.as_str() }, "(unknown)")
                        )
                    };
                    match status_message {
                        Err(e) => {
                            return Err((ParseError {
                                reason: format!("Unable to parse response to watch: {}", e),
                            }).into())
                        }
                        Ok(m) => {
                            return Err(ParseError {
                                reason: format!("Error from watch: {}", m),
                            }.into())
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

struct Looper<S>
where
    S: Stream<Item = (), Error = ()>,
{
    stream: S,
}

impl<S> Future for Looper<S>
where
    S: Stream<Item = (), Error = ()>,
{
    type Error = ();
    type Item = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Ok(Async::Ready(_)) = self.stream.poll() {
            ()
        }
        Ok(Async::NotReady)
    }
}

fn main_() -> Result<(), Error> {
    let client = Client::new()?;

    let req_builder = Box::new(|opts: RequestOpts| {
        Pod::list_core_v1_namespaced_pod(
            "kube-system",
            opts.continu_,
            None,
            None,
            None,
            None,
            None,
            opts.resource_version,
            None,
            Some(opts.watch),
        )
    });

    let stream = client
        .observe::<PodList, WatchEvent, Status, Vec<u8>>(req_builder)?
        .then(|result| -> Result<(), ()> {
            match result {
                Ok(Observed::List(l)) => {
                    l.items.iter().for_each(|pod| print_pod_state(&pod));
                }
                Ok(Observed::ListPart(l)) => {
                    l.items.iter().for_each(|pod| print_pod_state(&pod));
                }
                Ok(Observed::Item(event)) => {
                    if let Err(e) = handle_pod_event(event) {
                        println!("Error parsing pod event: {}", e);
                    }
                }
                Err(KubernetesError::Status(s)) => {
                    println!("Encountered error: {:#?}", s);
                }
                Err(KubernetesError::Other(e)) => {
                    println!("Encountered error: {}", e);
                }
            }

            Ok(())
        });

    rt::run(Looper { stream });

    Ok(())
}

fn main() {
    pretty_env_logger::init();
    let status = match main_() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {}", e);
            for c in e.iter_chain().skip(1) {
                eprintln!(" Caused by {}", c);
            }
            error!("Backtrace: {}", e.backtrace());
            1
        }
    };
    ::std::process::exit(status);
}
