use clap::Parser;

#[derive(Parser)]
#[command(name = "Transaction Decoder")]
#[command(version = "1.0")]
#[command(about = "Bitcoin Transaction Decoder", long_about = None)]
struct Cli {
    #[arg(
        required = true,
        help = "(string, required) Raw transaction hex"
    )]
    transaction_hex: String
}

fn main() {
    // let transaction_hex = "01000000021b04470fa0e6a5c5a1b406b7136cb00a550214310b3d659eed5720ec1d5ebafa16000000da004730440220137dbf6aa0cc89c64d2c224af794cd24d9e28df2d9c84af6f521f31623d5ea730220395e417fee49db252f3eaff8c5cccbed7ac60ee0f32b5017a76bb20f9b37798e01483045022100d80bf3887af3fcf006c9f300d0ec82e0a03d81d36f735794c037bcdefcec086e02201ce4d47478cb438aed860fc5eab28cc763d464af5aa0a249f2737a081afd35d50147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b61210377f8715b7895e57dd49de1ef084f94e6edb7df0f9e4807b94800ce751430004c52aeffffffff2a04e7374dd90a033120d3182db77d502210ecfb21a4499f8458e3f464b8e1e4020000006b483045022100992206f9b180553f07742ace393a6eb9542a5e704a3de55b57a2a112cd722c8c02206b040aeb7b3172dbae2e02344710a8174887d69614dddd034e08a07e5b296e8d012102ec4ce6f13fef0cd94532693d0d45a2f28dec2d3c8e693a5134da9d4c6dc0d16cffffffff02cdfb07000000000017a9142743d98a6175c25c9353c42b2feb8c09c769c4d387f4344b00000000001976a914714c6982c9f1c3560deceee9264eb193a737a69988ac00000000";

    let cli = Cli::parse();
    match transaction_decoder::decode(cli.transaction_hex) {
        Ok(json) => {
            println!("transaction {}", json);
        },
        Err(err) => {
            eprintln!("An error occurred: {}", err)
        }
    }
}