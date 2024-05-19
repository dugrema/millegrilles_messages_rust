pub const DOMAINE_NOM: &str = "Messages";
pub const COLLECTION_NOM: &str = DOMAINE_NOM;

pub const COLLECTION_RECEPTION_NOM: &str = "Messages/reception";
pub const COLLECTION_USAGERS_NOM: &str = "Messages/usagers";

pub const QUEUE_VOLATILS_NOM: &str = "Messages/volatils";
pub const QUEUE_TRIGGERS_NOM: &str = "Messages/triggers";
pub const REQUETE_SYNC_MESSAGES: &str = "syncMessages";
pub const REQUETE_DECHIFFRER_CLES: &str = "dechiffrerCles";
pub const REQUETE_MESSAGES_PAR_IDS: &str = "getMessagesParIds";
pub const REQUETE_RECLAMATIONS: &str = "reclamations";

pub const COMMANDE_POSTER_V1: &str = "posterV1";
pub const COMMANDE_MARQUER_LU: &str = "marquerLu";
pub const COMMANDE_SUPPRIMER_MESSAGE: &str = "supprimerMessage";
pub const COMMANDE_ASSOCIER_IMAGES: &str = "associerImages";
pub const COMMANDE_ASSOCIER_VIDEOS: &str = "associerVideos";

pub const EVENEMENT_NOUVEAU_MESSAGE: &str = "nouveauMessage";
pub const EVENEMENT_MESSAGE_LU: &str = "messageLu";
pub const EVENEMENT_MESSAGE_SUPPRIME: &str = "messageSupprime";


pub const VERSION_TRANSACTION_MESSAGE_1: u16 = 1;


pub const CHAMP_USER_ID: &str = "user_id";
pub const CHAMP_MESSAGE_ID: &str = "message_id";
