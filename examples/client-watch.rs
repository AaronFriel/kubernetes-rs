extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate serde_json;
extern crate failure;
extern crate kubernetes;
#[macro_use] extern crate log;
extern crate pretty_env_logger;

use std::result::Result;
use failure::Error;
use futures::prelude::*;
use tokio_core::reactor::Core;

use kubernetes::api;
use kubernetes::client::{Client,ListOptions};
use kubernetes::api::core::v1::{Pod,PodList,ContainerState};
use kubernetes::api::meta::v1::EventType;

fn print_pod_state(p: &Pod) {
    println!("pod {} - {:?}",
             p.metadata.name.as_ref().map(String::as_str).unwrap_or("(no name)"),
             p.status.phase.unwrap_or(api::core::v1::PodPhase::Unknown));
    let c_statuses = p.status.init_container_statuses.iter()
        .chain(p.status.container_statuses.iter());
    for c in c_statuses {
        print!("  -> {}: ", c.name);
        match c.state {
            None => println!("state unknown"),
            Some(ContainerState::Waiting(ref s)) =>
                println!("waiting: {}",
                         s.message.as_ref()
                         .or(s.reason.as_ref())
                         .map(String::as_str)
                         .unwrap_or("waiting")),
            Some(ContainerState::Running(ref s)) => {
                print!("running");
                if let Some(ref t) = s.started_at {
                    print!(" since {}", t);
                }
                println!("");
            },
            Some(ContainerState::Terminated(ref s)) => {
                if let Some(ref msg) = s.message {
                    println!("terminated: {}", msg);
                } else {
                    print!("exited with code {}", s.exit_code);
                    if let Some(ref t) = s.finished_at {
                        print!(" at {}", t);
                    }
                    println!("");
                }
            },
        }
    }
}

fn main_() -> Result<(),Error> {
    let mut core = Core::new()?;
    let client = Client::new(2, &core.handle())?;

    let pods = api::core::v1::GROUP_VERSION.with_resource("pods");
    let namespace = Some("kube-system");

    let work = client.list(&pods, namespace, Default::default())
        .inspect(|podlist: &PodList| {
            podlist.items.iter().for_each(print_pod_state);
        })
        .and_then(|podlist: PodList| {
            debug!("Starting at resource version {}", podlist.metadata.resource_version);

            let listopts = ListOptions { resource_version: podlist.metadata.resource_version, ..Default::default() };
            client.watch_list(&pods, namespace, listopts)
                .for_each(|event| {
                    match event.typ {
                        EventType::Added|EventType::Modified => {
                            let p: Pod = serde_json::from_value(event.object)?;
                            print_pod_state(&p);
                        },
                        EventType::Deleted => {
                            let p: Pod = serde_json::from_value(event.object)?;
                            println!("deleted {}",
                                     p.metadata.name.as_ref().map(String::as_str).unwrap_or("(no name)"));
                        },
                        EventType::Error => debug!("Ignoring error event {:#?}", event.object),
                    }
                    Ok(())
                })
        });

    core.run(work)?;

    Ok(())
}

fn main() {
    pretty_env_logger::init();
    let status = match main_() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {}", e);
            for c in e.causes().skip(1) {
                eprintln!(" Caused by {}", c);
            }
            debug!("Backtrace: {}", e.backtrace());
            1
        },
    };
    ::std::process::exit(status);
}
