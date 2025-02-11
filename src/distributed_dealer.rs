use std::{collections::BTreeMap, default};

use eyre::bail;
use frost_ristretto255::{
    self as frost,
    keys::{
        dkg::{
            round1::{self, SecretPackage},
            round2,
        },
        KeyPackage, PublicKeyPackage,
    },
    Identifier, Signature,
};
use rand::{CryptoRng, RngCore};
use tokio::sync::broadcast::{Receiver, Sender};

#[derive(Debug, Clone)]
enum Message {
    Round1 {
        sender_id: Identifier,
        round1_package: round1::Package,
    },

    Round2 {
        sender_id: Identifier,
        for_id: Identifier,
        round2_package: round2::Package,
    },
}

#[derive(Debug, PartialEq)]
enum DkgState {
    Round1 {
        secret_package: round1::SecretPackage,
        round1_packages: BTreeMap<Identifier, round1::Package>,
    },
    Round2 {
        secret_package: round2::SecretPackage,
        round1_packages: BTreeMap<Identifier, round1::Package>,
        round2_packages: BTreeMap<Identifier, round2::Package>,
    },
}

// TODO: Nice place to rewrite to libp2p, rough implementation anyway
//
struct Participiant {
    id: Identifier,
    broadcast_rx: Receiver<Message>,
    broadcast_tx: Sender<Message>,
    max_signers: u16,
    min_signers: u16,
}

impl Participiant {
    fn new(max_signers: u16, min_signers: u16, tx: Sender<Message>) -> Self {
        let id = format!("id-{:?}", rand::thread_rng());
        let id = Identifier::derive(id.as_bytes()).expect("works");

        let this = Self {
            id,
            broadcast_rx: tx.subscribe(),
            broadcast_tx: tx,
            max_signers,
            min_signers,
        };

        this
    }

    async fn run(mut self) -> eyre::Result<(PublicKeyPackage, KeyPackage)> {
        let (secret_package, round1_package) = frost::keys::dkg::part1(
            self.id,
            self.max_signers,
            self.min_signers,
            &mut rand::thread_rng(),
        )?;

        self.broadcast_tx.send(Message::Round1 {
            sender_id: self.id,
            round1_package,
        })?;

        let mut state_opt = Some(DkgState::Round1 {
            secret_package,
            round1_packages: BTreeMap::new(),
        });

        while let Ok(message) = self.broadcast_rx.recv().await {
            let state = state_opt.take().unwrap();
            state_opt = Some(match (state, message) {
                (
                    DkgState::Round1 {
                        secret_package,
                        mut round1_packages,
                    },
                    Message::Round1 {
                        sender_id: id,
                        round1_package: package,
                    },
                ) => {
                    if id == self.id {
                        continue;
                    }

                    round1_packages.insert(id, package);

                    if round1_packages.len() > self.min_signers.into() {
                        let (round2_secret_package, round2_packages) =
                            frost::keys::dkg::part2(secret_package, &round1_packages)?;

                        for (for_id, package) in round2_packages {
                            self.broadcast_tx.send(Message::Round2 {
                                sender_id: id,
                                for_id,
                                round2_package: package,
                            })?;
                        }

                        DkgState::Round2 {
                            secret_package: round2_secret_package,
                            round1_packages,
                            round2_packages: Default::default(),
                        }
                    } else {
                        DkgState::Round1 {
                            secret_package,
                            round1_packages,
                        }
                    }
                }
                (
                    DkgState::Round2 {
                        secret_package,
                        round1_packages,
                        mut round2_packages,
                    },
                    Message::Round2 {
                        sender_id: id,
                        for_id,
                        round2_package,
                    },
                ) => {
                    if id == self.id {
                        continue;
                    }

                    if for_id != self.id {
                        // NOTE: no auth, so just designate which signer will receive package
                        continue;
                    }

                    round2_packages.insert(id, round2_package);

                    if round2_packages.len() > self.min_signers.into() {
                        let (key_package, pubkey_package) = frost::keys::dkg::part3(
                            &secret_package,
                            &round1_packages,
                            &round2_packages,
                        )?;

                        return Ok((pubkey_package, key_package));
                    } else {
                        DkgState::Round2 {
                            secret_package,
                            round1_packages,
                            round2_packages,
                        }
                    }
                }
                (state, message) => {
                    bail!("Unexpected message {message:?} for state {state:?}")
                }
            })
        }

        bail!("shutting down");
    }
}

pub async fn sign(message: &[u8], max_signers: u16, min_signers: u16) -> eyre::Result<Signature> {
    let (tx, _rx1) = tokio::sync::broadcast::channel::<Message>(max_signers.into());
    let mut participiants =
        std::iter::repeat_with(|| Participiant::new(max_signers, min_signers, tx.clone()))
            .take(max_signers.into());

    let participiant1 = participiants.next().unwrap();

    for p in participiants {
        tokio::spawn(async move {
            p.run().await;
        });
    }

    let res = participiant1.run().await;

    println!("{res:?}");

    todo!()
}
