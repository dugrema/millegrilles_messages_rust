use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::domaine_messages::GestionnaireDomaineMessages;

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: MiddlewareMessages
{
    todo!()
}
