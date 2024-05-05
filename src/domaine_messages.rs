use log::{debug, info, warn};
use millegrilles_common_rust::{chrono, tokio};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{charger_certificats_chiffrage, Middleware};
use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::QueueType;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::static_cell::StaticCell;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::commandes::consommer_commande;
use crate::config_ressources::{preparer_index_mongodb_messages, preparer_queues};
use crate::constantes as Constantes;
use crate::constantes::{COLLECTION_NOM, COLLECTION_RECEPTION_NOM, COLLECTION_USAGERS_NOM, DOMAINE_NOM};
use crate::evenements::consommer_evenement;
use crate::requetes::consommer_requete;
use crate::transactions::aiguillage_transaction;

static GESTIONNAIRE: StaticCell<GestionnaireDomaineMessages> = StaticCell::new();


pub async fn run() {

    let (middleware, futures_middleware) = preparer_middleware()
        .expect("preparer middleware");
    let (gestionnaire, futures_domaine) = initialiser(middleware).await
        .expect("initialiser domaine");

    // Tester connexion redis
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                info!("redis.liste_certificats_fingerprints Resultat : {} certificats en cache", fingerprints_redis.len());
            },
            Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
        }
    }

    // Combiner les JoinHandles recus
    let mut futures = FuturesUnordered::new();
    futures.extend(futures_middleware);
    futures.extend(futures_domaine);

    // Demarrer thread d'entretien.
    futures.push(spawn(thread_entretien(gestionnaire, middleware)));

    // Le "await" maintien l'application ouverte. Des qu'une task termine, l'application arrete.
    futures.next().await;

    for f in &futures {
        f.abort()
    }

    info!("domaine_messages Attendre {} tasks restantes", futures.len());
    while futures.len() > 0 {
        futures.next().await;
    }

    info!("domaine_messages Fin execution");
}

async fn thread_entretien<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M)
    where M: Middleware
{
    let mut prochain_chargement_certificats_maitredescles = Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    // Attendre 5 secondes pour init bus
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    loop {
        let maintenant = Utc::now();

        // Effectuer entretien
        if prochain_chargement_certificats_maitredescles < maintenant {
            match charger_certificats_chiffrage(middleware).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                    debug!("domaines_core.entretien Prochain chargement cert maitredescles: {:?}", prochain_chargement_certificats_maitredescles);
                },
                Err(e) => warn!("domaines_core.entretien Erreur chargement certificats de maitre des cles : {:?}", e)
            }

        }

        // Sleep
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    }
}

/// Initialise le gestionnaire. Retourne les spawned tasks dans une liste de futures
/// (peut servir a canceller).
async fn initialiser<M>(middleware: &'static M) -> Result<(&'static GestionnaireDomaineMessages, FuturesUnordered<JoinHandle<()>>), Error>
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

    Ok((gestionnaire, futures))
}

#[derive(Clone)]
pub struct GestionnaireDomaineMessages {}

#[async_trait]
impl AiguillageTransactions for GestionnaireDomaineMessages {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
                                       -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for GestionnaireDomaineMessages {}

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
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        consommer_requete(self, middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        consommer_commande(self, middleware, message).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        consommer_evenement(self, middleware, message).await
    }
}
