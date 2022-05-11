use std::collections::HashMap;

use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_sdk::rpc::CkbRpcClient;
use ckb_sdk::traits::{
    DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
    DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
};
use ckb_sdk::tx_builder::transfer::CapacityTransferBuilder;
use ckb_sdk::tx_builder::{CapacityBalancer, TxBuilder};
use ckb_sdk::unlock::{ScriptUnlocker, SecpSighashScriptSigner, SecpSighashUnlocker};
use ckb_sdk::{GenesisInfo, ScriptId};
use ckb_types::bytes::Bytes;
use ckb_types::core::ScriptHashType;
use ckb_types::packed::{Byte32, CellOutput, Script, ScriptBuilder, WitnessArgs};
use ckb_types::prelude::*;
use trampoline_sdk::account::{Account};

use anyhow::anyhow;
use anyhow::Result;

// Required by parse_hex to check if the result is valid.
pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<()> {
    if src.is_empty() {
        return Err(anyhow!("Invalid length in dst {}", dst.len()));
    }
    let len = dst.len().checked_mul(2).unwrap();
    if src.len() < len || ((src.len() & 1) != 0) {
        return Err(anyhow!(
            "Invalid length in dst {}, expected: {}",
            dst.len(),
            len
        ));
    }
    hex::decode_to_slice(src, dst)?;

    Ok(())
}

// Parses a hex string into a byte array
// Used for creating a lock_arg for a Script
pub fn parse_hex(mut input: &str) -> Result<Vec<u8>> {
    if input.starts_with("0x") || input.starts_with("0X") {
        input = &input[2..];
    }
    if input.len() % 2 != 0 {
        return Err(anyhow!("Invalid hex string lenth: {}", input.len()));
    }
    let mut bytes = vec![0u8; input.len() / 2];
    hex_decode(input.as_bytes(), &mut bytes)
        .map_err(|err| anyhow!(format!("parse hex string failed: {:?}", err)))?;
    Ok(bytes)
}

// Lock Trait for creating diverse locks
trait Lock {
    fn as_script(&self) -> Script;
}

// SigHashAllLock
pub struct SigHashAllLock {
    hash_type: ScriptHashType,
    code_hash: Byte32,
    lock_arg: String,
}

impl SigHashAllLock {
    pub fn from_arg(arg_string: String) -> Self {
        Self {
            hash_type: ScriptHashType::Type,
            code_hash: SIGHASH_TYPE_HASH.pack(),
            lock_arg: arg_string,
        }
    }

    pub fn from_account(a: Account) -> Self {
        let lock_arg = a.lock_arg_hex();
        Self {
            hash_type: ScriptHashType::Type,
            code_hash: SIGHASH_TYPE_HASH.pack(),
            lock_arg: lock_arg,
        }
    }
}

impl Lock for SigHashAllLock {
    fn as_script(&self) -> Script {
        let lock_arg = parse_hex(&self.lock_arg).unwrap().pack();
        ScriptBuilder::default()
            .hash_type(self.hash_type.into())
            .code_hash(self.code_hash.clone())
            .args(lock_arg)
            .build()
    }
}

// TrampolineProvider
// Wrapper for ckb_sdk modules:
//   * CellDepResolver
//   * HeaderDepResolver
//   * CellCollector
//   * TransactionDependencyProvider
struct TrampolineProvider {
    node_url: String,
    indexer_url: String,
}

impl TrampolineProvider {
    pub fn new(node_url: &str, indexer_url: &str) -> Self {
        Self {
            node_url: node_url.to_string(),
            indexer_url: indexer_url.to_string(),
        }
    }

    pub fn cell_collector(&self) -> DefaultCellCollector {
        DefaultCellCollector::new(self.indexer_url.as_str(), self.node_url.as_str())
    }

    pub fn cell_dep_resolver(&self) -> DefaultCellDepResolver {
        let mut ckb_client = CkbRpcClient::new(self.node_url.as_str());
        let genesis_block = ckb_client.get_block_by_number(0.into()).unwrap().unwrap();
        let info = GenesisInfo::from_block(&ckb_types::core::BlockView::from(genesis_block))
            .expect("Failed creating genesis info from block");
        DefaultCellDepResolver::new(&info)
    }

    pub fn header_dep_resolver(&self) -> DefaultHeaderDepResolver {
        DefaultHeaderDepResolver::new(self.node_url.as_str())
    }

    pub fn tx_dep_provider(&self) -> DefaultTransactionDependencyProvider {
        DefaultTransactionDependencyProvider::new(self.node_url.as_str(), 10)
    }
}

fn main() {
    // The set up:
    // 0. This example assumes a CKB node is running at port 8114 of localhost
    //    and an indexer is running at 8116.
    let node_url = "http://localhost:8114";
    let indexer_url = "http://localhost:8116";

    // 1. First we define the parameters of our transaction.
    //    We must specify a sender Account and a destionation Account
    //    and the amount of CKB to send.
    //    For simplicity, both use the same password.
    let password = b"123456";

    // Set up sender account
    let sender_pk = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
    let sender = Account::from_secret(sender_pk.into(), password).unwrap();

    // Set up destination account using a given ckb address
    // TODO: Account should provide a method for getting mainnet and testnet addresses
    let destination_acc = Account::new(password).unwrap();

    // Set up amount to send
    let amount = 356_000_000_000u64;

    // 2. Next we connect to the node and indexer and get consensus data.

    // We use the node and indexer URLs to set up a TrampolineProvider instance
    let trampoline_provider = TrampolineProvider::new(node_url, indexer_url);

    // Create scripts unlocker

    // ATM this is the only way to access a decrypt key, it does not flush memory, nor is temporal
    // ckb_wallet crate implements TimedKeys which seem to be the way to go
    // Option B is implementing CKB in Wagyu, the cryptocurrency wallet framework
    let key = sender.crypto.decrypt_key(password).unwrap();
    let secret = secp256k1::SecretKey::from_slice(&key).unwrap();

    // Create signer
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secret]);
    let sighash_signer = SecpSighashScriptSigner::new(Box::new(signer));
    let sighash_unlocker = SecpSighashUnlocker::new(sighash_signer);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Create Balancer
    let sender_lockscript = SigHashAllLock::from_account(sender).as_script();
    println!("{}", &sender_lockscript);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender_lockscript, placeholder_witness, 1000);

    // Now we build the transaction
    let destination_lock = SigHashAllLock::from_account(destination_acc);
    let output = CellOutput::new_builder()
        .lock(destination_lock.as_script())
        .capacity(amount.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);

    // Build providers
    let mut cell_collector = trampoline_provider.cell_collector();
    let cell_dep_resolver = trampoline_provider.cell_dep_resolver();
    let header_dep_resolver = trampoline_provider.header_dep_resolver();
    let tx_dep_provider = trampoline_provider.tx_dep_provider();

    let (tx, locked_groups) = builder
        .build_unlocked(
            &mut cell_collector,
            // Maybe get some .clone() getters for each of these and use them instead of borrowing
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )
        .expect("Failed building tx");
    assert!(locked_groups.is_empty());

    println!("{:?}", tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_from_devchain_default_pk_creates_correct_lock_arg() {
        let pk = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
        let account = Account::from_secret(pk.into(), b"testpass").unwrap();
        let lockhash = account.lock_arg_hex();
        assert_eq!(
            format!("{}", lockhash),
            "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
        );
    }
}
