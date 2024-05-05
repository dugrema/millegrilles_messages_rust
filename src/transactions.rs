use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
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
use crate::constantes;
use crate::constantes::COLLECTION_RECEPTION_NOM;

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
        _ => Err(format!("transactions.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))?
    }
}

#[derive(Serialize, Deserialize)]
pub struct TransactionRecevoirMessage {
    user_id: String,
    message: DataChiffre,
    version: u16,
}

impl TransactionRecevoirMessage {
    pub fn new<S>(user_id: S, message: DataChiffre) -> Self
        where S: ToString
    {
        Self { user_id: user_id.to_string(), message, version: constantes::VERSION_TRANSACTION_MESSAGE_1 }
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

    Ok(None)
}
