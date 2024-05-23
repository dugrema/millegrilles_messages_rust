use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::constantes as CommonConstantes;
use millegrilles_common_rust::mongodb::options::UpdateOptions;

use serde::{Deserialize, Serialize};
use crate::commandes::MessageFichierV1;
use crate::constantes;
use crate::constantes::{COLLECTION_FICHIERS_NOM, COLLECTION_RECEPTION_NOM};

use crate::domaine_messages::GestionnaireDomaineMessages;

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: TryInto<TransactionValide> + Send
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(Error::Str("aiguillage_transaction Erreur try_into TransactionValide"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.aiguillage_transaction Transaction sans action : {}", transaction.transaction.id))?
        },
        None => Err(format!("transactions.aiguillage_transaction Transaction sans routage : {}", transaction.transaction.id))?
    };

    match action.as_str() {
        constantes::COMMANDE_POSTER_V1 => transaction_poster_v1(gestionnaire, middleware, transaction).await,
        constantes::COMMANDE_MARQUER_LU => transaction_marquer_lu(gestionnaire, middleware, transaction).await,
        constantes::COMMANDE_SUPPRIMER_MESSAGE => transaction_supprimer_message(gestionnaire, middleware, transaction).await,
        _ => Err(format!("transactions.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

#[derive(Serialize, Deserialize)]
pub struct FichierMessage {
    fuuid: String,
    taille_chiffre: i64,
    cle_id: String,
    format: String,
    #[serde(skip_serializing_if="Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    verification: Option<String>,
}

impl From<&MessageFichierV1> for FichierMessage {
    fn from(value: &MessageFichierV1) -> Self {
        Self {
            fuuid: value.fuuid.clone(),
            taille_chiffre: value.taille_chiffre,
            cle_id: value.cle_id.clone(),
            format: value.format.clone(),
            nonce: value.nonce.clone(),
            verification: value.verification.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TransactionRecevoirMessage {
    user_id: String,
    message: DataChiffre,
    #[serde(skip_serializing_if="Option::is_none")]
    fichiers: Option<Vec<FichierMessage>>,
    version: u16,
}

impl TransactionRecevoirMessage {
    pub fn new<S>(user_id: S, message: DataChiffre, fichiers: Option<Vec<FichierMessage>>) -> Self
        where S: ToString
    {
        Self { user_id: user_id.to_string(), message, fichiers, version: constantes::VERSION_TRANSACTION_MESSAGE_1 }
    }
}

async fn transaction_poster_v1<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MongoDao
{
    let message_id = transaction.transaction.id;
    let message_recu: TransactionRecevoirMessage = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let user_id = message_recu.user_id;
    let estampille = transaction.transaction.estampille;

    let filtre = doc! {"message_id": &message_id};
    let datachiffre_value = convertir_to_bson(message_recu.message)?;
    let ops = doc!{
        "$setOnInsert": {
            "user_id": &user_id,
            "message": datachiffre_value,
            "date_traitement": &estampille,
            "lu": false,
            CommonConstantes::CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true}
    };
    let collection = middleware.get_collection(COLLECTION_RECEPTION_NOM)?;
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre, ops, options).await?;

    if let Some(fichiers) = message_recu.fichiers {
        for fichier in fichiers {
            let filtre = doc!{"user_id": &user_id, "message_id": &message_id, "fuuid": fichier.fuuid, "cle_id": fichier.cle_id};
            let ops = doc!{
                "$setOnInsert": {
                    "nonce": fichier.nonce,
                    "format": fichier.format,
                    "verification": fichier.verification,
                    "taille_chiffre": fichier.taille_chiffre,
                    CommonConstantes::CHAMP_CREATION: Utc::now()
                },
                "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true}
            };
            let collection = middleware.get_collection(COLLECTION_FICHIERS_NOM)?;
            let options = UpdateOptions::builder().upsert(true).build();
            collection.update_one(filtre, ops, options).await?;
        }
    }

    Ok(None)
}

#[derive(Deserialize)]
pub struct TransactionMarquerLu {
    pub message_ids: Vec<String>,
}

async fn transaction_marquer_lu<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, transaction: TransactionValide)
                                  -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MongoDao
{
    let message_recu: TransactionMarquerLu = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("transaction_marquer_lu Certificat sans user_id"))?
    };

    let message_ids = message_recu.message_ids;

    // Verifier que l'usager a acces au message et qu'il n'a pas deja lu==true
    let filtre = doc!{constantes::CHAMP_USER_ID: &user_id, constantes::CHAMP_MESSAGE_ID: {"$in": &message_ids}};
    let ops = doc! {
        "$set": {"lu": true},
        "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(COLLECTION_RECEPTION_NOM)?;
    collection.update_many(filtre, ops, None).await?;

    Ok(None)
}

#[derive(Deserialize)]
pub struct TransactionSupprimerMessage {
    pub message_ids: Vec<String>,
}

async fn transaction_supprimer_message<M>(_gestionnaire: &GestionnaireDomaineMessages, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MongoDao
{
    let message_recu: TransactionSupprimerMessage = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("transaction_supprimer_message Certificat sans user_id"))?
    };

    let message_ids = message_recu.message_ids;

    // Supprimer les messages
    let filtre = doc!{constantes::CHAMP_USER_ID: &user_id, constantes::CHAMP_MESSAGE_ID: {"$in": &message_ids}};
    let collection = middleware.get_collection(COLLECTION_RECEPTION_NOM)?;
    collection.delete_many(filtre.clone(), None).await?;

    // Supprimer les fichiers associes au message
    let collection_fichiers = middleware.get_collection(COLLECTION_FICHIERS_NOM)?;
    collection_fichiers.delete_many(filtre.clone(), None).await?;

    Ok(None)
}
