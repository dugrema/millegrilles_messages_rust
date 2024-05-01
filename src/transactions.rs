use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;

use crate::domaine_messages::GestionnaireDomaineMessages;

pub async fn aiguillage_transaction<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    todo!()
}
