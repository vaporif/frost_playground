mod distributed_dealer;
mod trusted_dealer;

fn main() -> eyre::Result<()> {
    let max_signers = 5;
    let min_signers = 3;
    let message = "random message";
    let signature = trusted_dealer::sign(message.as_bytes(), max_signers, min_signers);

    println!("signature is {:?}", signature);

    Ok(())
}
