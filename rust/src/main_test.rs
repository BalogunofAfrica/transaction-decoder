use std::io::Read;
use serde::{Serialize, Serializer};

#[derive(Debug, Serialize)]
struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>
}

#[derive(Debug, Serialize)]
struct  Input {
    // txid: [u8; 32],
    txid: String,
    output_index: u32,
    // script_sig: Vec<u8>,
    script_sig: String,
    sequence: u32,
}

#[derive(Debug, Serialize)]
struct Output {
    #[serde(serialize_with = "as_btc")]
    amount: Amount,
    script_pub_key: String
}

trait BitcoinValue {
    fn to_btc(&self) -> f64;
}

#[derive(Debug)]
struct Amount(u64);

impl BitcoinValue for Amount {
    fn to_btc(&self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }
}

fn as_btc<S: Serializer, T: BitcoinValue>(t: &T, s: S) -> Result<S::Ok,S::Error> {
    let btc = t.to_btc();
    s.serialize_f64(btc)
}


// impl fmt::Debug for Input {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Input")
//         .field("txid", &self.txid)
//         .field("output_index", &self.output_index)
//         .field("script_sig", &self.script_sig)
//         .field("sequence", &self.sequence)
//         .finish()
//     }
// }

fn read_compact_size(transaction_bytes: &mut &[u8]) -> u64 {
    let mut compact_size = [0_u8; 1];
    transaction_bytes.read(&mut compact_size).unwrap();
    

    match compact_size[0] {
       0..=252 => compact_size[0] as u64,
       253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read(&mut  buffer).unwrap();
            u16::from_le_bytes(buffer) as u64
       },
       254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read(&mut  buffer).unwrap();
            u32::from_le_bytes(buffer) as u64
       }, 
       255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read(&mut  buffer).unwrap();
            u64::from_le_bytes(buffer)
        }
    }

    // if (0..253).contains(&compact_size[0]) {
    //     compact_size[0] as u64
    // } else if compact_size[0] == 253 {
    // } else if compact_size[0] == 254 {
    //     let mut buffer = [0; 4];
    //     transaction_bytes.read(&mut  buffer).unwrap();
    //     u32::from_le_bytes(buffer) as u64
    // } 
    // else {
    //     let mut buffer = [0; 8];
    //     transaction_bytes.read(&mut  buffer).unwrap();
    //     u64::from_le_bytes(buffer)
    // }
}

#[allow(unused_variables)]
fn read_u32(transaction_bytes: &mut &[u8]) -> u32 {
    // let transaction_bytes = hex::decode(hex).unwrap();
    // let version_bytes = <[u8; 4]>::try_from( &transaction_bytes[0..4]).unwrap();
    // let version_bytes: [u8; 4] = (&transaction_bytes[0..4]).try_into().unwrap();

    // let num_inputs = transaction_bytes[4];
    // println!("num inputs is {}", num_inputs);
    // let mut bytes_slice = transaction_bytes.as_slice();
    // let mut buffer = [0; 4];
    // bytes_slice.read(&mut buffer).unwrap();
    // u32::from_le_bytes(buffer)

    let mut buffer = [0; 4];
    transaction_bytes.read(&mut buffer).unwrap();
    u32::from_le_bytes(buffer)
}

fn read_amount(transaction_bytes: &mut &[u8]) -> Amount {
    let mut buffer = [0; 8];
    transaction_bytes.read(&mut buffer).unwrap();
    Amount(u64::from_le_bytes(buffer))
}

fn read_txid(transaction_bytes: &mut &[u8]) -> String {
    let mut buffer = [0; 32];
    transaction_bytes.read(&mut buffer).unwrap();
    buffer.reverse();
    hex::encode(buffer)
}

fn read_script(transaction_bytes: &mut &[u8]) -> String {
    let script_size = read_compact_size(transaction_bytes) as usize;
    let mut buffer = vec![0_u8; script_size];
    transaction_bytes.read(&mut buffer).unwrap();
    hex::encode(buffer)
}

fn main() {
    let transaction_hex = "01000000021b04470fa0e6a5c5a1b406b7136cb00a550214310b3d659eed5720ec1d5ebafa16000000da004730440220137dbf6aa0cc89c64d2c224af794cd24d9e28df2d9c84af6f521f31623d5ea730220395e417fee49db252f3eaff8c5cccbed7ac60ee0f32b5017a76bb20f9b37798e01483045022100d80bf3887af3fcf006c9f300d0ec82e0a03d81d36f735794c037bcdefcec086e02201ce4d47478cb438aed860fc5eab28cc763d464af5aa0a249f2737a081afd35d50147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b61210377f8715b7895e57dd49de1ef084f94e6edb7df0f9e4807b94800ce751430004c52aeffffffff2a04e7374dd90a033120d3182db77d502210ecfb21a4499f8458e3f464b8e1e4020000006b483045022100992206f9b180553f07742ace393a6eb9542a5e704a3de55b57a2a112cd722c8c02206b040aeb7b3172dbae2e02344710a8174887d69614dddd034e08a07e5b296e8d012102ec4ce6f13fef0cd94532693d0d45a2f28dec2d3c8e693a5134da9d4c6dc0d16cffffffff02cdfb07000000000017a9142743d98a6175c25c9353c42b2feb8c09c769c4d387f4344b00000000001976a914714c6982c9f1c3560deceee9264eb193a737a69988ac00000000";
    let transaction_bytes = hex::decode(transaction_hex).unwrap();
    let mut bytes_slice = transaction_bytes.as_slice();
    let version = read_u32(&mut bytes_slice);
    let input_count = read_compact_size(&mut bytes_slice);
    let mut inputs = vec![];
    
    for _ in 0..input_count {
        let txid = read_txid(&mut bytes_slice);
        let output_index = read_u32(&mut bytes_slice);
        let script_sig = read_script(&mut bytes_slice);
        let sequence = read_u32(&mut  bytes_slice);

        let input = Input{
            output_index, script_sig, sequence, txid
        };
        inputs.push(input);
    }

    let output_count = read_compact_size(&mut bytes_slice);
    let mut outputs = vec![];

    for _ in 0..output_count {
        let amount= read_amount(&mut  bytes_slice);
        let script_pub_key = read_script(&mut bytes_slice);

        outputs.push(Output{
            amount,
            script_pub_key
        });
    }

    let transaction = Transaction{ inputs, version, outputs};

    // let json_inputs = serde_json::to_string_pretty(&inputs).unwrap();
    println!("version: {}", version);
    println!("input length: {}", input_count);
    println!("transaction {}", serde_json::to_string_pretty(&transaction).unwrap());
}

#[cfg(test)]
mod test {
    use crate::read_compact_size;

    #[test]
    fn test_read_compact_size() {
        let mut bytes = [1_u8].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 1_u64);
        
        let mut bytes: &[u8] = [253_u8, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64);

        let mut bytes: &[u8] = [254_u8, 1, 1, 0, 0].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 257_u64);

        let mut bytes: &[u8] = [255_u8, 1, 1, 1, 0, 0, 0, 0, 0].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 65793_u64);

        let hex = "fd204e";
        let decoded = hex::decode(hex).unwrap();
        let mut bytes = decoded.as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 20_000_u64);
    }
}