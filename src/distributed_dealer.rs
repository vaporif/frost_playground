use std::collections::{BTreeMap, HashMap};

use frost_ristretto255::{
    self as frost,
    keys::{PublicKeyPackage, SecretShare},
    round1::SigningCommitments,
    round2::SignatureShare,
    Identifier,
};

pub struct Coordinator {
    pub public_key_package: PublicKeyPackage,
    pub nonces: HashMap<Identifier, SigningCommitments>,
    pub shares: HashMap<Identifier, SignatureShare>,
}

impl Coordinator {
    fn generate(
        max_signers: u16,
        min_signers: u16,
    ) -> eyre::Result<(BTreeMap<Identifier, SecretShare>, Self)> {
        let (shares, public_key_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rand::thread_rng(),
        )?;

        Ok((
            shares,
            Coordinator {
                public_key_package,
                nonces: HashMap::new(),
                shares: HashMap::new(),
            },
        ))
    }
}
