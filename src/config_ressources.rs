use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{DEFAULT_Q_TTL, Securite};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};

use crate::constantes::{COMMANDE_ASSOCIER_IMAGES, COMMANDE_ASSOCIER_VIDEOS, COMMANDE_MESSAGE_LU, COMMANDE_POSTER_V1, COMMANDE_SUPPRIMER_MESSAGE, DOMAINE_NOM, QUEUE_VOLATILS_NOM, REQUETE_DECHIFFRER_CLES, REQUETE_MESSAGES_PAR_IDS, REQUETE_RECLAMATIONS, REQUETE_SYNC_MESSAGES};
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
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_MESSAGE_LU), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SUPPRIMER_MESSAGE), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_ASSOCIER_IMAGES), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_ASSOCIER_VIDEOS), exchange: Securite::L3Protege});

    // Evenements
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS_NOM, EVENEMENT_FICHIERS_SYNCPRET), exchange: Securite::L2Prive});

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
    // let options_cle_id = IndexOptions {
    //     nom_index: Some(String::from(INDEX_CLE_ID)),
    //     unique: true,
    // };
    // let champs_index_cle_id = vec!(
    //     ChampIndex {nom_champ: String::from(CHAMP_CLE_ID), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     nom_collection_cles,
    //     champs_index_cle_id,
    //     Some(options_cle_id)
    // ).await?;

    Ok(())
}
