use std::str::from_utf8;
use std::time::Duration;
use log::{debug, error};

use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite, EVENEMENT_CEDULE, DOMAINE_FICHIERS, COMMANDE_ACTIVITE_FUUIDS};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::options::FindOptions;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::json;

use crate::constantes;
use crate::domaine_messages::GestionnaireDomaineMessages;

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MiddlewareMessages + MongoDao
{
    debug!("consommer_evenement : {:?}", &message.type_message);
    verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Evenement(r) => r.action.clone(),
        _ => Err(Error::Str("evenements.consommer_evenement Mauvais type message, doit etre Evenement"))?
    };

    match action.as_str() {
        // Commandes standard
        EVENEMENT_CEDULE => Ok(None),  // Skip
        // constantes::EVENEMENT_FICHIERS_SYNCPRET => evenement_fichiers_syncpret(middleware, message).await,
        // EVENEMENT_FICHIERS_VISITER_FUUIDS => evenement_visiter_fuuids(middleware, m).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_evenement: Evenement {} inconnu, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }

}

/// Verifier si le message est autorise a etre execute comme requete. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(), Error> {
    match message.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                true => Ok(()),
                false => Err(Error::String(format!(
                    "verifier_autorisation: Commande autorisation invalide pour message {:?}",
                    message.type_message))),
            }
        }
    }
}
