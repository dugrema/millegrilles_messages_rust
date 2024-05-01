use std::sync::Arc;
use log::{info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines::{GestionnaireDomaine, GestionnaireMessages};
use millegrilles_common_rust::domaines_traits::{ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::static_cell::StaticCell;

use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::QueueType;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::Receiver;
use millegrilles_common_rust::transactions::TraiterTransaction;
use crate::config_ressources::{preparer_index_mongodb_messages, preparer_queues};

use crate::constantes as Constantes;
use crate::constantes::{COLLECTION_NOM, COLLECTION_RECEPTION_NOM, COLLECTION_USAGERS_NOM, DOMAINE_NOM};

static GESTIONNAIRE: StaticCell<GestionnaireDomaineMessages> = StaticCell::new();


pub async fn run() {

    let middleware = preparer_middleware().expect("preparer middleware");
    let gestionnaire = initialiser(middleware).await.expect("initialiser domaine");

    // Tester connexion redis
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                info!("redis.liste_certificats_fingerprints Resultat : {} certificats en cache", fingerprints_redis.len());
            },
            Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
        }
    }

    // Creer threads de traitement
    spawn_threads(gestionnaire, middleware).await.expect("spawn threads domaine messages");

    tokio::time::sleep(tokio::time::Duration::from_secs(45)).await;

    // // ** Thread d'entretien **
    // futures.push(spawn(entretien(middleware.clone())));
    //
    // // Thread ecoute et validation des messages
    // info!("domaines_maitredescles.build Ajout {} futures dans middleware_hooks", futures.len());
    // for f in middleware_hooks.futures {
    //     futures.push(f);
    // }
    //
    // futures
}

async fn initialiser<M>(middleware: &'static M) -> Result<&'static GestionnaireDomaineMessages, Error>
    where M: Middleware
{
    let gestionnaire = GestionnaireDomaineMessages {};
    let gestionnaire = GESTIONNAIRE.try_init(gestionnaire)
        .expect("gestionnaire init");

    // Preparer la collection avec index
    let futures = gestionnaire.initialiser(middleware).await
        .expect("initialiser");

    // Preparer des ressources additionnelles
    preparer_index_mongodb_messages(middleware, gestionnaire).await
        .expect("preparer_index_mongodb_messages");

    Ok(gestionnaire)
}

async fn spawn_threads<M>(gestionnaire: &'static GestionnaireDomaineMessages, middleware: &'static M)
    -> Result<(), Error>
    where M: MongoDao
{
    Ok(())
}

#[derive(Clone)]
pub struct GestionnaireDomaineMessages {}

#[async_trait]
impl GestionnaireDomaineSimple for GestionnaireDomaineMessages {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: ValidateurX509 + GenerateurMessages + MongoDao {
        todo!()
    }
}

impl GestionnaireDomaineV2 for GestionnaireDomaineMessages {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(COLLECTION_NOM.to_string())
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, Error> {
        Ok(vec![
            COLLECTION_RECEPTION_NOM.to_string(),
            COLLECTION_USAGERS_NOM.to_string(),
        ])
    }
}

impl GestionnaireBusMillegrilles for GestionnaireDomaineMessages {
    fn get_nom_domaine(&self) -> String {
        DOMAINE_NOM.to_string()
    }

    fn get_q_volatils(&self) -> String {
        Constantes::QUEUE_VOLATILS_NOM.to_string()
    }

    fn get_q_triggers(&self) -> String {
        Constantes::QUEUE_TRIGGERS_NOM.to_string()
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues()
    }
}

#[async_trait]
impl ConsommateurMessagesBus for GestionnaireDomaineMessages {
    async fn consommer_messages<M>(&self, middleware: &M, rx: Receiver<TypeMessage>) where M: MiddlewareMessages {
        todo!()
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: MiddlewareMessages {
        todo!()
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: MiddlewareMessages {
        todo!()
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: MiddlewareMessages {
        todo!()
    }
}

#[async_trait]
impl TraiterTransaction for GestionnaireDomaineMessages {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        todo!()
    }
}
