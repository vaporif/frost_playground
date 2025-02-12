use std::collections::BTreeMap;

use frost_ristretto255::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage, SecretShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};

pub fn sign(message: &[u8], max_signers: u16, min_signers: u16) -> eyre::Result<Signature> {
    let coordinator = Coordinator::generate(max_signers, min_signers).expect("always succeds");
    coordinator.sign(message)
}
struct Coordinator {
    pub public_key_package: PublicKeyPackage,
    pub participiants: BTreeMap<Identifier, Participiant>,
}

impl Coordinator {
    fn generate(max_signers: u16, min_signers: u16) -> eyre::Result<Self> {
        let (shares, public_key_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rand::thread_rng(),
        )?;

        let participiants: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, secret_share)| {
                (
                    id,
                    Participiant::new(id, secret_share).expect("succeeds always"),
                )
            })
            .collect();

        Ok(Coordinator {
            public_key_package,
            participiants,
        })
    }

    fn sign(mut self, message: &[u8]) -> eyre::Result<Signature> {
        let signing_commitments: BTreeMap<Identifier, SigningCommitments> = self
            .participiants
            .iter_mut()
            .map(|(id, participiant)| (*id, participiant.round1()))
            .collect();

        let signing_package = frost::SigningPackage::new(signing_commitments, message);

        let signature_shares: BTreeMap<Identifier, SignatureShare> = self
            .participiants
            .iter_mut()
            .map(|(id, participiant)| {
                (*id, participiant.round2(&signing_package).expect("succeds"))
            })
            .collect();

        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )
        .expect("signature should succeed");

        let is_signature_valid = &self
            .public_key_package
            .verifying_key()
            .verify(message, &group_signature)
            .is_ok();

        assert!(is_signature_valid);

        Ok(group_signature)
    }
}

pub struct Participiant {
    #[allow(dead_code)]
    pub id: Identifier,
    pub key_package: KeyPackage,
    pub nonces: Option<SigningNonces>,
}

impl Participiant {
    fn new(id: Identifier, secret_share: SecretShare) -> eyre::Result<Self> {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;

        Ok(Self {
            id,
            key_package,
            nonces: None,
        })
    }

    fn round1(&mut self) -> frost::round1::SigningCommitments {
        let (nonces, signing_commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut rand::thread_rng());

        self.nonces = Some(nonces);
        signing_commitments
    }

    fn round2(
        &mut self,
        signing_package: &SigningPackage,
    ) -> eyre::Result<frost::round2::SignatureShare> {
        let signature_share = frost::round2::sign(
            signing_package,
            &self.nonces.take().unwrap(),
            &self.key_package,
        )?;
        Ok(signature_share)
    }
}
