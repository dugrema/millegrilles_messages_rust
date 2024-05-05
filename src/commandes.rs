use std::collections::{HashMap, HashSet};
use std::str::from_utf8;

use log::{debug, error, warn};
use millegrilles_common_rust::{constantes as CommonConstantes, serde_json};
use millegrilles_common_rust::base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64_nopad};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage};
use millegrilles_common_rust::constantes::{COMMANDE_AJOUTER_CLE_DOMAINES, DELEGATION_GLOBALE_PROPRIETAIRE, DOMAINE_NOM_MAITREDESCLES, DOMAINE_NOM_MAITREDESCOMPTES, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, RolesCertificats, Securite};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{Cipher, CleChiffrageHandler};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher};
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::generer_cle_avec_ca;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::{MongoDao, opt_chrono_datetime_as_bson_datetime};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::constantes;
use crate::constantes::{COLLECTION_USAGERS_NOM, DOMAINE_NOM};
use crate::domaine_messages::GestionnaireDomaineMessages;
use crate::transactions::TransactionRecevoirMessage;

pub async fn consommer_commande<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("consommer_commande : {:?}", &message.type_message);
    let (_user_id, _role_prive) = verifier_autorisation(&message)?;

    let action = match &message.type_message {
        TypeMessageOut::Commande(r) => r.action.clone(),
        _ => Err(Error::Str("grosfichiers.consommer_commande Mauvais type message, doit etre Commande"))?
    };

    match action.as_str() {
        // Commandes standard
        constantes::COMMANDE_POSTER_V1 => commande_poster_v1(gestionnaire, middleware, message).await,

        // Commande inconnue
        _ => Err(Error::String(format!("consommer_commande: Commande {} inconnue, **DROPPED**\n{}",
                                       action, from_utf8(message.message.buffer.as_slice())?)))?,
    }
}

/// Verifier si le message est autorise  a etre execute comme commonde. Lance une erreur si le
/// message doit etre rejete.
fn verifier_autorisation(message: &MessageValide) -> Result<(Option<String>, bool), Error> {
    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, commande usager
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

// *********
// Commandes
// *********

#[derive(Serialize)]
struct ReponseCommandePoster {
    ok: bool,
    code: Option<usize>,
    err: Option<String>,
}

async fn commande_poster_v1<M>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler + ValidateurX509
{
    let message_ref = message.message.parse()?;

    let dechiffrage = match message_ref.dechiffrage.as_ref() {
        Some(inner) => inner,
        None => Err(Error::Str("commande_poster_v1 Message sans chiffrage - **REJETE**"))?
    };

    let cles = match dechiffrage.cles.as_ref() {
        Some(inner) => inner,
        None => Err(Error::Str("commande_poster_v1 Message sans cles chiffrees - **REJETE**"))?
    };

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_signature.fingerprint()?;

    let cle_dechiffrage = match cles.get(fingerprint.as_str()) {
        Some(inner) => {
            let mut cle_buffer = [0u8;32];
            todo!("Dechiffrer cle");
            // cle_buffer.copy_from_slice(&cle_secrete[0..32]);
            CleSecreteX25519 {0: cle_buffer}
        },
        None => {
            debug!("commande_poster_v1 Cle locale non presente dans dechiffrage, faire une requete de dechiffrage aupres du maitre des cles");
            let routage = RoutageMessageAction::builder(
                DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE,
                vec![Securite::L3Protege]
            )
                .timeout_blocking(5000)
                .build();
            let reponse_dechiffrage = match middleware.transmettre_requete(routage, dechiffrage).await {
                Ok(inner) => {
                    match inner {
                        Some(inner) => match inner {
                            TypeMessage::Valide(inner) => inner,
                            _ => Err(Error::Str("commande_poster_v1 Mauvais type de reponse sur requete dechiffrage cles"))?
                        },
                        None => Err(Error::Str("commande_poster_v1 Aucune reponse sur requete dechiffrage cles"))?
                    }
                },
                Err(e) => {
                    error!("commande_poster_v1 Erreur requete dechiffrage message : {:?}", e);
                    let reponse = ReponseCommandePoster { ok: false, code: Some(3), err: Some("Timeout serveur".to_string()) };
                    return Ok(Some(middleware.build_reponse(&reponse)?.0))
                }
            };

            let reponse_dechiffrage_ref = reponse_dechiffrage.message.parse()?;
            let contenu: ReponseDechiffrageMessage = reponse_dechiffrage_ref.dechiffrer(enveloppe_signature.as_ref())?;
            debug!("commande_poster_v1 Reponse dechiffrage ref : {:?}", contenu);
            let cle_secrete = match contenu.cle_secrete_base64 {
                Some(inner) => base64_nopad.decode(inner)?,
                None => Err(Error::Str("commande_poster_v1 Aucune cle secrete inclue"))?
            };
            let mut cle_buffer = [0u8;32];
            cle_buffer.copy_from_slice(&cle_secrete[0..32]);
            CleSecreteX25519 {0: cle_buffer}
        }
    };

    // Dechiffrer le contenu du message
    let resultat: MessagePostV1 = message_ref.dechiffrer_avec_secret(cle_dechiffrage)?;

    debug!("commande_poster_v1 Message dechiffre recu :\n{:?}", resultat);

    // Recuperer profil de l'usager. Generer au besoin.
    let (profils, mut cles_chiffrage, destinataire_manquants) = match get_profils_usagers(middleware, &resultat.destinataires).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("commande_poster_v1 Erreur get_profils_usagers : {:?}", e);
            let reponse = ReponseCommandePoster { ok: true, code: Some(500), err: Some("Erreur traitement destinataires".to_string()) };
            return Ok(Some(middleware.build_reponse(&reponse)?.0))
        }
    };

    let nombre_profils = profils.len();
    if nombre_profils == 0 {
        debug!("Message recu n'a aucun destinataire correspondant");
        let reponse = ReponseCommandePoster { ok: true, code: Some(1), err: Some("Destinataires inconnus".to_string()) };
        return Ok(Some(middleware.build_reponse(&reponse)?.0))
    }

    // Generer la transaction pour chaque profil usager
    for profil in profils {
        let cle_id = match profil.cle_id {
            Some(inner) => inner,
            None => {
                error!("commande_poster_v1 Cle_id de chiffrage manquante pour profil {}, skip destinataire", profil.user_id);
                continue
            }
        };
        let cle_secrete = match cles_chiffrage.remove(&cle_id) {
            Some(inner) => inner,
            None => {
                error!("commande_poster_v1 Cle de chiffrage manquante pour profil {}, skip destinataire", profil.user_id);
                continue
            }
        };
        sauvegarder_message(gestionnaire, middleware, profil.user_id.as_str(), cle_id, cle_secrete, &resultat).await?;
    }

    let (code, err) = if destinataire_manquants.len() > 0 {
        (200, Some(format!("Message traite pour {} destinataires. {} destinataires sont inconnus",
                           nombre_profils, destinataire_manquants.len())))
    } else {
        (201, None)
    };

    let reponse = ReponseCommandePoster { ok: true, code: Some(code), err };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn sauvegarder_message<M,S,K>(gestionnaire: &GestionnaireDomaineMessages, middleware: &M,
                                    user_id: S, cle_id: K, cle_secrete: CleSecreteX25519,
                                    message: &MessagePostV1
)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao, S: ToString, K: ToString
{
    let mut cipher = CipherMgs4::with_secret(CleSecreteCipher::CleSecrete(cle_secrete))?;
    let message_bytes = serde_json::to_string(&message)?;
    let taille_chiffrage = (message_bytes.len() as f64 * 1.05 + 17f64) as usize;
    let mut buffer = Vec::with_capacity(taille_chiffrage);
    buffer.resize(taille_chiffrage, 0u8);
    let taille_contenu = cipher.update(message_bytes.as_bytes(), buffer.as_mut_slice())?;
    let resultat_chiffrage = cipher.finalize(&mut buffer[taille_contenu..])?;

    // Tronquer le buffer pour garder la taille exacte
    buffer.truncate(taille_contenu + resultat_chiffrage.len);

    let info_dechiffrage = resultat_chiffrage.cles;
    let format_chiffrage: &str = info_dechiffrage.format.into();

    let message_chiffre = DataChiffre {
        data_chiffre: base64_nopad.encode(buffer),
        format: Some(format_chiffrage.to_string()),
        cle_id: Some(cle_id.to_string()),
        nonce: info_dechiffrage.nonce,
        verification: info_dechiffrage.verification,
        // Champs obsolete
        header: None, ref_hachage_bytes: None, hachage_bytes: None,
    };

    let transaction_message = TransactionRecevoirMessage::new(user_id, message_chiffre);
    sauvegarder_traiter_transaction_serializable_v2(middleware, &transaction_message, gestionnaire,
        DOMAINE_NOM, constantes::COMMANDE_POSTER_V1).await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ProfilUsagerMessages {
    /// User_id interne defini par le maitre des comptes.
    user_id: String,

    /// Nom de l'usager. Reset regulierement pour reverifier aupres du maitre des comptes.
    nom_usager: Option<String>,

    /// Cle_id courant pour le chiffrage des messages de cet usager.
    /// Reset automatiquement regulierement pour generer une nouvelle cle.
    cle_id: Option<String>,

    // /// Date du dernier reset de nom_usager et cle_id
    //#[serde(default, skip_serializing_if="Option::is_none", with="opt_chrono_datetime_as_bson_datetime")]
    //dernier_reset: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct RequeteUsersMaitredescomptes {
    noms_usagers: Vec<String>
}

#[derive(Deserialize)]
struct ReponseUsersMaitredescomptes {
    usagers: HashMap<String, String>
}

async fn get_profils_usagers<M,S>(middleware: &M, noms_usagers: &Vec<S>)
    -> Result<(Vec<ProfilUsagerMessages>, HashMap<String, CleSecreteX25519>, Vec<String>), Error>
    where
        M: MongoDao + GenerateurMessages + CleChiffrageHandler,
        S: AsRef<str>
{
    let noms_usagers: Vec<&str> = noms_usagers.iter().map(|s| s.as_ref()).collect();
    let mut manquants: HashSet<&str> = HashSet::with_capacity(noms_usagers.len());
    manquants.extend(noms_usagers.iter());

    let enveloppe_signature = middleware.get_enveloppe_signature();

    // Charger profils usagers connus
    let mut profils= find_usagers_messages(middleware, FiltreUsagerChamp::NomUsager(noms_usagers)).await?;
    let mut cles_chiffrage: HashMap<String, CleSecreteX25519> = HashMap::new();
    for p in &profils {
        debug!("get_profils_usagers Profil trouve : {:?}", p);
        if let Some(nom_usager) = p.nom_usager.as_ref() {
            manquants.remove(nom_usager.as_str());

            // Charger la cle de chiffrage si presente
            if let Some(cle_id) = &p.cle_id {
                let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege])
                    .timeout_blocking(3000)
                    .build();
                let requete = RequeteDechiffrage {
                    domaine: DOMAINE_NOM.to_string(),
                    liste_hachage_bytes: None,
                    cle_ids: Some(vec![cle_id.clone()]),
                    certificat_rechiffrage: None,
                };
                if let Ok(Some(TypeMessage::Valide(reponse))) = middleware.transmettre_requete(routage, requete).await {
                    let reponse_ref = reponse.message.parse()?;
                    let reponse_dechiffree: ReponseRequeteDechiffrageV2 = reponse_ref.dechiffrer(enveloppe_signature.as_ref())?;
                    if reponse_dechiffree.ok {
                        match reponse_dechiffree.cles {
                            Some(mut inner) => {
                                if inner.len() != 1 {
                                    Err(Error::Str("get_profils_usagers Mauvais nombre de cles dechiffrees recues"))?
                                }
                                let cle = inner.remove(0);
                                cles_chiffrage.insert(cle_id.to_owned(), cle.cle_secrete()?)
                            },
                            None => Err(Error::Str("get_profils_usagers Aucunes cles dechiffrees recues"))?
                        };
                    } else {
                        Err(Error::String(format!("get_profils_usagers Erreur requete cle dechiffrage : {:?}", reponse_dechiffree.err)))?
                    }
                } else {
                    Err(Error::Str("get_profils_usagers Erreur requete cle dechiffrage"))?
                }
            }
        }
    }

    // Recuperer user_ids pour les usagers, generer profils inconnus
    if manquants.len() > 0 {
        debug!("get_profils_usagers {} profils manquants, requete vers maitre des comptes", manquants.len());
        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCOMPTES, "getUserIdParNomUsager", vec![Securite::L3Protege])
            .timeout_blocking(3000)
            .build();
        let requete_contenu = RequeteUsersMaitredescomptes {noms_usagers: manquants.iter().map(|s| s.to_string()).collect()};
        let reponse = middleware.transmettre_requete(routage, requete_contenu).await.unwrap_or_else(|e| {
            error!("get_profils_usagers Erreur requete maitre des comptes : {:?}", e);
            None
        });
        if let Some(TypeMessage::Valide(reponse)) = reponse {
            debug!("get_profils_usagers Reponse liste comptes\n{}", from_utf8(reponse.message.buffer.as_slice())?);
            let reponse_ref = reponse.message.parse()?;
            let reponse_usagers: ReponseUsersMaitredescomptes = reponse_ref.contenu()?.deserialize()?;

            let collection = middleware.get_collection_typed::<ProfilUsagerMessages>(COLLECTION_USAGERS_NOM)?;
            for (nom_usager, user_id) in &reponse_usagers.usagers {
                let filtre = doc!{"user_id": user_id};
                let ops = doc! {
                    "$set": {"nom_usager": nom_usager},
                    "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true, "dernier_reset": true},
                };
                let options = FindOneAndUpdateOptions::builder()
                    .upsert(true)
                    .return_document(ReturnDocument::After)
                    .build();
                let profil = match collection.find_one_and_update(filtre, ops, options).await? {
                    Some(inner) => inner,
                    None => Err(Error::Str("get_profils_usagers Erreur creation compte profile usager: aucun resultat sur upsert"))?
                };
                profils.push(profil);
                manquants.remove(nom_usager.as_str());
            }

            if manquants.len() > 0 {
                debug!("get_profils_usagers Profils manquants : {}", manquants.len());
            }
        } else {
            warn!("get_profils_usagers Erreur reponse liste comptes - aucune reponse ou mauvais type");
        }
    }

    // Generer les cles pour profils
    let enveloppe_ca = enveloppe_signature.enveloppe_ca.as_ref();
    let enveloppes_chiffrage = middleware.get_publickeys_chiffrage();
    if enveloppes_chiffrage.len() == 0 {
        Err(Error::Str("Aucunes cles de maitre des cles connues"))?
    }
    let enveloppes_chiffrage_ref: Vec<&EnveloppeCertificat> = enveloppes_chiffrage.iter().map(|e| e.as_ref()).collect();
    let domaines = vec![DOMAINE_NOM];
    for p in &mut profils {
        if p.cle_id.is_none() {
            // Generer cle pour usager
            let (dechiffrage, cle) = generer_cle_avec_ca(domaines.clone(), enveloppe_ca, enveloppes_chiffrage_ref.clone())?;

            // Conserver cle aupres du maitre des cles
            let routage_cle = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public])
                .timeout_blocking(5000)
                .build();
            let mut cles = HashMap::new();
            match dechiffrage.cles {
                Some(inner) => {
                    for (fingerprint, val) in inner {
                        cles.insert(fingerprint, val);
                    }
                },
                None => Err(Error::Str("get_profils_usagers Aucunes cles generees par generer_cle_avec_ca"))?
            }

            let signature_domaines = match dechiffrage.signature {
                Some(inner) => inner,
                None => Err(Error::Str("get_profils_usagers Aucune signature generee par generer_cle_avec_ca"))?
            };

            let commande = CommandeAjouterCleDomaine {
                cles,
                signature: signature_domaines.clone(),
            };
            if let Ok(Some(TypeMessage::Valide(message))) = middleware.transmettre_commande(routage_cle, commande).await {
                let message_ref = message.message.parse()?;
                let message_contenu = message_ref.contenu()?;
                let reponse_etat: ReponseCommande = message_contenu.deserialize()?;
                if let Some(true) = reponse_etat.ok {
                    // Ok, sauvegarder cle_id dans profil
                    let cle_id = signature_domaines.get_cle_ref()?.to_string();
                    let filtre = doc!{"user_id": &p.user_id};
                    let ops = doc! {
                        "$set": {"cle_id": &cle_id},
                        "$currentDate": {CommonConstantes::CHAMP_MODIFICATION: true}
                    };
                    let collection = middleware.get_collection(COLLECTION_USAGERS_NOM)?;
                    if collection.update_one(filtre, ops, None).await?.modified_count != 1 {
                        Err(Error::String(format!("get_profils_usagers Erreur sauvegarde cle_id pour profil {} - SKIP", p.user_id)))?
                    }
                    p.cle_id = Some(cle_id.clone());
                    cles_chiffrage.insert(cle_id, cle.secret);
                } else {
                    Err(Error::String(format!("get_profils_usagers Erreur sauvegarde cle aupres du maitre des cles : {:?}", reponse_etat)))?
                }
            } else {
                Err(Error::Str("get_profils_usagers Erreur sauvegarde nouvelle cle profil aupres du maitre des cles"))?
            }
        }
    }

    if cles_chiffrage.len() != profils.len() {
        Err(Error::Str("get_profils_usagers Mismatch nombre de cles de chiffrage et profils"))?
    }

    debug!("Generer les transactions de nouveau message pour {} destinataire(s)", profils.len());

    Ok((profils, cles_chiffrage, manquants.iter().map(|s| s.to_string()).collect()))
}

enum FiltreUsagerChamp<S> where S: ToString {
    // UserId(Vec<S>),
    NomUsager(Vec<S>),
}

async fn find_usagers_messages<M,S>(middleware: &M, usagers: FiltreUsagerChamp<S>)
    -> Result<Vec<ProfilUsagerMessages>, Error>
    where M: MongoDao, S: ToString
{
    let (filtre, nombre_usagers) = match usagers {
        // FiltreUsagerChamp::UserId(u) => {
        //     let liste: Vec<String> = u.iter().map(|s|s.to_string()).collect();
        //     (doc! {"user_id":{"$in": liste}}, u.len())
        // }
        FiltreUsagerChamp::NomUsager(u) => {
            let liste: Vec<String> = u.iter().map(|s|s.to_string()).collect();
            (doc! {"nom_usager":{"$in": liste}}, u.len())
        }
    };
    let collection = middleware.get_collection_typed::<ProfilUsagerMessages>(COLLECTION_USAGERS_NOM)?;
    let mut curseur = collection.find(filtre, None).await?;
    let mut profils = Vec::with_capacity(nombre_usagers);
    while let Some(row) = curseur.next().await {
        let profil = match row {
            Ok(inner) => inner,
            Err(e) => {
                error!("get_profils_usagers Erreur chargement profil : {:?}", e);
                continue
            }
        };
        profils.push(profil);
    }
    Ok(profils)
}

#[derive(Debug, Deserialize)]
struct ReponseDechiffrageMessage {
    ok: bool,
    err: Option<String>,
    cle_secrete_base64: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessagePostV1 {
    /// Contenu HTML du message
    contenu: String,
    /// Liste de destinataires (noms usagers)
    destinataires: Vec<String>,
    /// Information pour repondre au message.
    #[serde(skip_serializing_if="Option::is_none")]
    reply_to: Option<String>,
    /// Date de creation du message du point de vue de l'origine
    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    date_post: Option<DateTime<Utc>>,
    /// Information non structuree sur l'origine du message.
    origine: Option<String>,
}
