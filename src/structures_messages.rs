use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::dechiffrage::{DataChiffre, DataChiffreBorrow};
use serde::Deserialize;
use millegrilles_common_rust::bson;

#[derive(Deserialize)]
pub struct MessageDbRef<'a> {
    pub message_id: &'a str,
    #[serde(rename="_mg-derniere-modification", with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub derniere_modification: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub date_traitement: DateTime<Utc>,

    /// Champs optionnels pour permettre projection reduite (e.g. pour sync)
    pub lu: Option<bool>,
    pub supprime: Option<bool>,
    pub message: Option<DataChiffreBorrow<'a>>,
}

#[derive(Deserialize)]
pub struct MessageDb {
    pub message_id: String,
    #[serde(rename="_mg-derniere-modification", with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub derniere_modification: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub date_traitement: DateTime<Utc>,
    pub lu: bool,
    pub supprime: Option<bool>,
    pub message: DataChiffre,
}
