use std::collections::BTreeMap;

use eyre::bail;
use frost_ristretto255::{
    self as frost,
    keys::{
        dkg::{
            round1::{self},
            round2,
        },
        KeyPackage, PublicKeyPackage,
    },
    Identifier, Signature,
};
use rand::RngCore;
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
        round1_secret_package: round1::SecretPackage,
        round1_packages: BTreeMap<Identifier, round1::Package>,
    },
    Round2 {
        round2_secret_package: round2::SecretPackage,
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
    is_tracing: bool,
}

impl Participiant {
    fn new(max_signers: u16, min_signers: u16, tx: Sender<Message>) -> Self {
        let id = format!("id-{:?}", rand::thread_rng().next_u64());
        let id = Identifier::derive(id.as_bytes()).expect("works");

        Self {
            id,
            broadcast_rx: tx.subscribe(),
            broadcast_tx: tx,
            max_signers,
            min_signers,
            is_tracing: false,
        }
    }

    async fn run(mut self) -> eyre::Result<(PublicKeyPackage, KeyPackage)> {
        let (secret_package, round1_package) = frost::keys::dkg::part1(
            self.id,
            self.max_signers,
            self.min_signers,
            rand::thread_rng(),
        )?;

        self.broadcast_tx.send(Message::Round1 {
            sender_id: self.id,
            round1_package,
        })?;

        let mut state_opt = Some(DkgState::Round1 {
            round1_secret_package: secret_package,
            round1_packages: BTreeMap::new(),
        });

        loop {
            match self.broadcast_rx.recv().await {
                Ok(message) => {
                    //if self.is_tracing {
                    //    println!("message {message:?}");
                    //}

                    let state = state_opt.take().unwrap();

                    state_opt = Some(match (state, message) {
                        (
                            DkgState::Round1 {
                                round1_secret_package: secret_package,
                                mut round1_packages,
                            },
                            Message::Round1 {
                                sender_id: id,
                                round1_package: package,
                            },
                        ) => {
                            if id != self.id {
                                round1_packages.insert(id, package);
                            }

                            if round1_packages.len() > self.min_signers.into() {
                                let (round2_secret_package, round2_packages) =
                                    frost::keys::dkg::part2(secret_package, &round1_packages)?;

                                for (for_id, package) in round2_packages {
                                    self.broadcast_tx.send(Message::Round2 {
                                        sender_id: self.id,
                                        for_id,
                                        round2_package: package,
                                    })?;
                                }

                                DkgState::Round2 {
                                    round2_secret_package,
                                    round1_packages,
                                    round2_packages: Default::default(),
                                }
                            } else {
                                DkgState::Round1 {
                                    round1_secret_package: secret_package,
                                    round1_packages,
                                }
                            }
                        }
                        (
                            DkgState::Round2 {
                                round2_secret_package: secret_package,
                                round1_packages,
                                mut round2_packages,
                            },
                            Message::Round2 {
                                sender_id: id,
                                for_id,
                                round2_package,
                            },
                        ) => {
                            // NOTE: no auth, so just designate which signer will receive package
                            if for_id == self.id {
                                round2_packages.insert(id, round2_package);

                                if self.is_tracing {
                                    println!("added package, len is {}", round2_packages.len());
                                }
                            }

                            if self.is_tracing {
                                println!(
                                    "round2 packages len {}, need {}",
                                    round2_packages.len(),
                                    self.min_signers
                                );
                            }

                            if round2_packages.len() > self.min_signers.into() {
                                let (key_package, pubkey_package) = frost::keys::dkg::part3(
                                    &secret_package,
                                    &round1_packages,
                                    &round2_packages,
                                )?;

                                return Ok((pubkey_package, key_package));
                            } else {
                                DkgState::Round2 {
                                    round2_secret_package: secret_package,
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
                Err(error) => {
                    return Err(eyre::eyre!(error));
                }
            }
        }
    }
}

pub async fn sign(_message: &[u8], max_signers: u16, min_signers: u16) -> eyre::Result<Signature> {
    let (tx, _rx1) = tokio::sync::broadcast::channel::<Message>(1000);
    let mut participiants =
        std::iter::repeat_with(|| Participiant::new(max_signers, min_signers, tx.clone()))
            .take(max_signers.into());

    let mut participiant1 = participiants.next().unwrap();
    participiant1.is_tracing = true;

    for p in participiants {
        tokio::spawn(async move {
            _ = p.run().await;
        });
    }

    let res = participiant1.run().await;

    println!("{res:?}");

    todo!()
}
