use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{DEFAULT_Q_TTL, Securite, DOMAINE_FICHIERS};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};

use crate::constantes::{COMMANDE_ASSOCIER_IMAGES, COMMANDE_ASSOCIER_VIDEOS, COMMANDE_MARQUER_LU, COMMANDE_POSTER_V1, COMMANDE_SUPPRIMER_MESSAGE, DOMAINE_NOM, QUEUE_VOLATILS_NOM, REQUETE_DECHIFFRER_CLES, REQUETE_MESSAGES_PAR_IDS, REQUETE_RECLAMATIONS, REQUETE_SYNC_MESSAGES, COMMANDE_RECLAMER_FUUIDS, COLLECTION_USAGERS_NOM, COLLECTION_FICHIERS_NOM, COLLECTION_RECEPTION_NOM};

use crate::domaine_messages::GestionnaireDomaineMessages;

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // Requetes
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRER_CLES), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_SYNC_MESSAGES), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_MESSAGES_PAR_IDS), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_RECLAMATIONS), exchange: Securite::L4Secure});

    // Commandes
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_POSTER_V1), exchange: Securite::L1Public});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_MARQUER_LU), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SUPPRIMER_MESSAGE), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_RECLAMER_FUUIDS), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_ASSOCIER_IMAGES), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_ASSOCIER_VIDEOS), exchange: Securite::L3Protege});

    // Evenements
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_FICHIERS_SYNCPRET), exchange: Securite::L2Prive});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: QUEUE_VOLATILS_NOM.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_messages<M>(middleware: &M, gestionnaire: &GestionnaireDomaineMessages) -> Result<(), Error>
    where M: MongoDao + ConfigMessages
{
    let options_usagers = IndexOptions {
        nom_index: Some(String::from("user_id")),
        unique: true,
    };
    let champs_index_usagers = vec!(
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_USAGERS_NOM,
        champs_index_usagers,
        Some(options_usagers)
    ).await?;

    let options_fichiers = IndexOptions {
        nom_index: Some(String::from("message_fuuid_id")),
        unique: true,
    };
    let champs_index_fichiers = vec!(
        ChampIndex {nom_champ: String::from("message_id"), direction: 1},
        ChampIndex {nom_champ: String::from("fuuid"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_FICHIERS_NOM,
        champs_index_fichiers,
        Some(options_fichiers)
    ).await?;

    let options_reception_message_id = IndexOptions {
        nom_index: Some(String::from("message_id")),
        unique: true,
    };
    let champs_index_reception_message_id = vec!(
        ChampIndex {nom_champ: String::from("message_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_RECEPTION_NOM,
        champs_index_reception_message_id,
        Some(options_reception_message_id)
    ).await?;

    let options_reception_user_id = IndexOptions {
        nom_index: Some(String::from("user_id")),
        unique: false,
    };
    let champs_index_reception_user_id = vec!(
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTION_RECEPTION_NOM,
        champs_index_reception_user_id,
        Some(options_reception_user_id)
    ).await?;

    Ok(())
}
