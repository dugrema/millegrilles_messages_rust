use log::info;
use millegrilles_common_rust::tokio::runtime::Builder;

use crate::domaine_messages::run as run_messages;

mod domaine_messages;
mod constantes;
mod config_ressources;
mod commandes;
mod requetes;
mod evenements;
mod transactions;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");

    let runtime = Builder::new_multi_thread()
        // .worker_threads(3)  // Utiliser env var TOKIO_WORKER_THREADS
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(run_messages());
}
