mod distributed_dealer;
mod trusted_dealer;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let max_signers = 5;
    let min_signers = 3;
    let message = "random message";
    let signature = trusted_dealer::sign(message.as_bytes(), max_signers, min_signers);
    println!("signature is {:?}", signature);

    let (signature) = distributed_dealer::sign(message.as_bytes(), max_signers, min_signers)
        .await
        .expect("works");

    Ok(())
}
