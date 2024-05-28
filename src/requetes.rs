use std::collections::HashSet;
use std::str::from_utf8;
use log::{debug, error};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite, CHAMP_MODIFICATION, CHAMP_CREATION, DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::mongodb::options::FindOptions;

use serde::{Deserialize, Serialize};
use crate::constantes;
use crate::constantes::{COLLECTION_FICHIERS_NOM, COLLECTION_RECEPTION_NOM, DOMAINE_NOM};
use crate::domaine_messages::GestionnaireDomaineMessages;
use crate::structures_messages::{MessageDb, MessageDbRef};

pub async fn consommer_requete<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MiddlewareMessages + MongoDao
{
    debug!("consommer_requete : {:?}", &message.type_message);
    let (_user_id, _role_prive) = verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Requete(r) => r.action.clone(),
        _ => Err(Error::Str("grosfichiers.consommer_requete Mauvais type message, doit etre Requete"))?
    };

    match action.as_str() {
        // Commandes standard
        constantes::REQUETE_SYNC_MESSAGES => requete_sync_messages(gestionnaire, middleware, message).await,
        constantes::REQUETE_MESSAGES_PAR_IDS => requete_messages_par_ids(gestionnaire, middleware, message).await,
        constantes::REQUETE_DECHIFFRER_CLES => requete_dechiffrer_cles(gestionnaire, middleware, message).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_commande: Commande {} inconnue, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }

}

/// Verifier si le message est autorise a etre execute comme requete. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(Option<String>, bool), Error> {
    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, requete usager
    } else {
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
        }?;
    }

    Ok((user_id, role_prive))
}

// ********
// Requetes
// ********

#[derive(Serialize)]
struct MessageSyncInfo {
    message_id: String,
    #[serde(with="epochseconds")]
    derniere_modification: DateTime<Utc>,
    supprime: bool,
}

impl From<MessageDbRef<'_>> for MessageSyncInfo {
    fn from(value: MessageDbRef) -> Self {
        Self {
            message_id: value.message_id.to_string(),
            derniere_modification: value.derniere_modification,
            supprime: value.supprime.unwrap_or_else(||false),
        }
    }
}

#[derive(Serialize)]
struct ReponseSyncMessages {
    ok: bool,
    err: Option<String>,
    bucket: String,
    messages: Vec<MessageSyncInfo>
}

#[derive(Deserialize)]
struct RequeteSyncMessages {
    bucket: String,
    skip: Option<u64>,
    limit: Option<i64>,
}

async fn requete_sync_messages<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_sync_messages Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
    let message_ref = message.message.parse()?;
    let requete: RequeteSyncMessages = message_ref.contenu()?.deserialize()?;

    let skip = requete.skip.unwrap_or_else(|| 0);
    let limit = requete.limit.unwrap_or_else(|| 1000);

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("requete_sync_messages Certificat sans user_id"))?
    };

    let bucket: Bson = if requete.bucket.as_str() == "reception" {
        let bucket = doc!{"$exists": false};
        bucket.into()
    } else {
        Bson::String(requete.bucket.clone())
    };

    let filtre = doc! {"user_id": &user_id, "bucket": bucket};
    let options = FindOptions::builder()
        .skip(skip)
        .limit(limit)
        .projection(doc!{"message_id": 1, CHAMP_MODIFICATION: 1, "supprime": 1, "date_traitement": 1})
        .sort(doc!{CHAMP_CREATION: 1, "_id": 1})
        .build();
    let collection = middleware.get_collection_typed::<MessageDbRef>(COLLECTION_RECEPTION_NOM)?;
    let mut curseur = collection.find(filtre, options).await?;
    let mut resultat = Vec::with_capacity(limit as usize);
    while curseur.advance().await? {
        let row = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                error!("requete_sync_messages Erreur mapping row message, skip : {:?}", e);
                continue
            }
        };

        let message_sync = MessageSyncInfo::from(row);
        resultat.push(message_sync);
    }

    let reponse = ReponseSyncMessages {
        ok: true,
        err: None,
        bucket: requete.bucket,
        messages: resultat,
    };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteMessagesParIds {
    message_ids: Vec<String>
}

#[derive(Serialize)]
struct MessageReponse {
    pub message_id: String,
    #[serde(with="epochseconds")]
    pub derniere_modification: DateTime<Utc>,
    #[serde(with="epochseconds")]
    pub date_traitement: DateTime<Utc>,
    pub lu: bool,
    pub supprime: bool,
    pub message: DataChiffre,
}

impl From<MessageDb> for MessageReponse {
    fn from(value: MessageDb) -> Self {
        Self {
            message_id: value.message_id,
            derniere_modification: value.derniere_modification,
            date_traitement: value.date_traitement,
            lu: value.lu,
            supprime: value.supprime.unwrap_or_else(||false),
            message: value.message,
        }
    }
}

#[derive(Serialize)]
struct ReponseMessagesParIds {
    ok: bool,
    err: Option<String>,
    messages: Vec<MessageReponse>,
}

async fn requete_messages_par_ids<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_messages_par_ids Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
    let message_ref = message.message.parse()?;
    let requete: RequeteMessagesParIds = message_ref.contenu()?.deserialize()?;

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("requete_sync_messages Certificat sans user_id"))?
    };

    let filtre = doc! {"user_id": &user_id, "message_id": {"$in": requete.message_ids}};
    let collection = middleware.get_collection_typed::<MessageDb>(COLLECTION_RECEPTION_NOM)?;

    let mut messages: Vec<MessageReponse> = Vec::new();
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        messages.push(row.into());
    }

    let reponse = ReponseMessagesParIds { ok: true, err: None, messages };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteDechiffrerCles {
    cle_ids: Vec<String>,
    cles_fichiers: Option<bool>,
}

#[derive(Deserialize)]
struct MetadataChiffre<'a> {
    cle_id: &'a str,
}

#[derive(Deserialize)]
struct MessageCle<'a> {
    // message_id: &'a str,
    #[serde(borrow)]
    message: MetadataChiffre<'a>
}

#[derive(Deserialize)]
struct FichierCle<'a> {
    // message_id: &'a str,
    // fuuid: &'a str,
    cle_id: &'a str,
}

async fn requete_dechiffrer_cles<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_dechiffrer_cles Message recu {:?}\n{}", message.type_message, from_utf8(message.message.buffer.as_slice())?);
    let message_ref = message.message.parse()?;
    let requete: RequeteDechiffrerCles = message_ref.contenu()?.deserialize()?;

    let (reply_to, correlation_id) = match message.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_to = match r.reply_to {
                Some(inner) => inner,
                None => Err("requete_dechiffrer_cles Requete sans reply_to")?
            };
            let correlation_id = match r.correlation_id {
                Some(inner) => inner,
                None => Err("requete_dechiffrer_cles Requete sans correlation_id")?
            };
            (reply_to, correlation_id)
        },
        _ => Err(Error::Str("requete_dechiffrer_cles Mauvais type message, doit etre requete"))?
    };

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("requete_dechiffrer_cles Certificat sans user_id"))?
    };

    // S'assurer que l'usager a acces au cles demandees
    let mut cles = HashSet::new();

    if let Some(true) = requete.cles_fichiers {
        let filtre = doc!{"user_id": &user_id, "cle_id": {"$in": &requete.cle_ids}};
        let collection = middleware.get_collection_typed::<FichierCle>(COLLECTION_FICHIERS_NOM)?;
        let options = FindOptions::builder().projection(doc!("message_id": 1, "fuuid": 1, "cle_id": 1)).build();
        let mut curseur = collection.find(filtre, options).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            cles.insert(row.cle_id.to_string());
        }
    } else {
        let filtre = doc!{"user_id": &user_id, "message.cle_id": {"$in": &requete.cle_ids}};
        let collection = middleware.get_collection_typed::<MessageCle>(COLLECTION_RECEPTION_NOM)?;
        let options = FindOptions::builder().projection(doc!("message_id": 1, "message.cle_id": 1)).build();
        let mut curseur = collection.find(filtre, options).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            cles.insert(row.message.cle_id.to_string());
        }
    }

    if cles.len() > 0 {
        debug!("requete_dechiffrer_cles Requete pour dechiffrer {} cles", cles.len());
        let cles: Vec<String> = cles.into_iter().collect();

        let routage = RoutageMessageAction::builder(
            DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
            .reply_to(reply_to)
            .correlation_id(correlation_id)
            .blocking(false)
            .build();

        let requete = RequeteDechiffrage {
            domaine: DOMAINE_NOM.to_string(),
            liste_hachage_bytes: None,
            cle_ids: Some(cles),
            certificat_rechiffrage: Some(message.certificat.chaine_pem()?),
        };
        middleware.transmettre_requete(routage, requete).await?;

        // On ne retourne rien, le maitre des cles va repondre
        Ok(None)
    } else {
        // Refuse, les cles n'appartiennent pas a l'usager ou n'existent pas
        Ok(Some(middleware.reponse_err(1, None, Some("Acces refuse"))?))
    }
}