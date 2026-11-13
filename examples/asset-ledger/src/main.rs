//! Asset Ledger **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Tracks total supply, asset metadata, per-Identity balances, and delegated debit allowances
//! (`approve` / `transferFrom`) so Identity HPS accounts can hold assets and authorize settlement
//! contracts like `AssetPair_OTC` to atomically debit and credit balances.
//!
//! Supported ABI methods:
//! - `initialize(address issuer, string symbol, uint64 decimals)`
//! - `mint(address toIdentity, uint64 amount)`
//! - `burn(uint64 amount)`
//! - `transfer(address toIdentity, uint64 amount)`
//! - `approve(address spender, uint64 amount)`
//! - `transferFrom(address fromIdentity, address toIdentity, uint64 amount)`
//! - `balanceOf(address holder)` -> `uint256`
//! - `allowance(address owner, address spender)` -> `uint256`
//! - `totalSupply()` -> `uint256`
//! - `decimals()` -> `uint256`
//! - `issuer()` -> `address`
//! - `symbol()` -> `string`

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const TRANSFER_TOPIC: [u8; 32] = event_topic("Transfer(address,address,uint64)");
const APPROVAL_TOPIC: [u8; 32] = event_topic("Approval(address,address,uint64)");

const KEY_INIT: &[u8] = b"meta:init";
const KEY_ISSUER: &[u8] = b"meta:issuer";
const KEY_SYMBOL: &[u8] = b"meta:symbol";
const KEY_DECIMALS: &[u8] = b"meta:decimals";
const KEY_SUPPLY: &[u8] = b"meta:supply";

hps_entry! {
    "initialize(address,string,uint64)"       => handle_initialize,
    "mint(address,uint64)"                    => handle_mint,
    "burn(uint64)"                            => handle_burn,
    "transfer(address,uint64)"                => handle_transfer,
    "approve(address,uint64)"                 => handle_approve,
    "transferFrom(address,address,uint64)"    => handle_transfer_from,
    "balanceOf(address)"                      => handle_balance_of,
    "allowance(address,address)"              => handle_allowance,
    "totalSupply()"                           => handle_total_supply,
    "decimals()"                              => handle_decimals,
    "issuer()"                                => handle_issuer,
    "symbol()"                                => handle_symbol,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn balance_key(holder: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"bal:").push(holder)
}

fn allowance_key(owner: &[u8; 20], spender: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"alw:")
        .push(owner)
        .push(spender)
}

fn ensure_initialized() -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        Ok(())
    } else {
        Err(-10)
    }
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11); // already initialized
    }
    let issuer = args.address(0).ok_or(-3)?;
    let symbol = args.dynamic_bytes(1).ok_or(-3)?;
    let decimals = args.u64(2).ok_or(-3)?;

    if issuer == [0u8; 20] || symbol.is_empty() || symbol.len() > 32 {
        return Err(-12);
    }

    storage::set_address(KEY_ISSUER, &issuer);
    storage::set(KEY_SYMBOL, symbol);
    storage::set_u64(KEY_DECIMALS, decimals);
    storage::set_u64(KEY_INIT, 1);
    Ok(())
}

fn handle_mint(args: &CalldataReader) -> Result<(), i32> {
    ensure_initialized()?;
    let caller = context::msg_sender();
    let issuer = storage::get_address(KEY_ISSUER).ok_or(-10)?;
    if caller != issuer {
        return Err(-13); // unauthorized: only issuer may mint
    }

    let to = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    if to == [0u8; 20] || amount == 0 {
        return Err(-14);
    }

    let bk = balance_key(&to);
    let new_bal = storage::get_u64(bk.as_slice())
        .checked_add(amount)
        .ok_or(-15)?;
    let new_supply = storage::get_u64(KEY_SUPPLY)
        .checked_add(amount)
        .ok_or(-15)?;

    storage::set_u64(bk.as_slice(), new_bal);
    storage::set_u64(KEY_SUPPLY, new_supply);

    events::emit(
        &[TRANSFER_TOPIC, addr_topic(&[0u8; 20]), addr_topic(&to)],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(new_bal);
    Ok(())
}

fn handle_burn(args: &CalldataReader) -> Result<(), i32> {
    ensure_initialized()?;
    let amount = args.u64(0).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }
    let holder = context::msg_sender();
    let bk = balance_key(&holder);
    let bal = storage::get_u64(bk.as_slice());
    if bal < amount {
        return Err(-16); // insufficient balance
    }

    let next_bal = bal - amount;
    let next_supply = storage::get_u64(KEY_SUPPLY).saturating_sub(amount);
    storage::set_u64(bk.as_slice(), next_bal);
    storage::set_u64(KEY_SUPPLY, next_supply);

    events::emit(
        &[TRANSFER_TOPIC, addr_topic(&holder), addr_topic(&[0u8; 20])],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(next_bal);
    Ok(())
}

fn move_balance(from: &[u8; 20], to: &[u8; 20], amount: u64) -> Result<(), i32> {
    if *to == [0u8; 20] {
        return Err(-14);
    }
    let fk = balance_key(from);
    let from_bal = storage::get_u64(fk.as_slice());
    if from_bal < amount {
        return Err(-16); // insufficient balance
    }
    if from != to {
        let tk = balance_key(to);
        let to_bal = storage::get_u64(tk.as_slice())
            .checked_add(amount)
            .ok_or(-15)?;
        storage::set_u64(fk.as_slice(), from_bal - amount);
        storage::set_u64(tk.as_slice(), to_bal);
    }
    events::emit(
        &[TRANSFER_TOPIC, addr_topic(from), addr_topic(to)],
        &amount.to_be_bytes(),
    );
    Ok(())
}

fn handle_transfer(args: &CalldataReader) -> Result<(), i32> {
    ensure_initialized()?;
    let to = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let sender = context::msg_sender();
    move_balance(&sender, &to, amount)?;
    ret::write_bool(true);
    Ok(())
}

fn handle_approve(args: &CalldataReader) -> Result<(), i32> {
    ensure_initialized()?;
    let spender = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    if spender == [0u8; 20] {
        return Err(-14);
    }
    let owner = context::msg_sender();
    let ak = allowance_key(&owner, &spender);
    storage::set_u64(ak.as_slice(), amount);

    events::emit(
        &[APPROVAL_TOPIC, addr_topic(&owner), addr_topic(&spender)],
        &amount.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_transfer_from(args: &CalldataReader) -> Result<(), i32> {
    ensure_initialized()?;
    let from = args.address(0).ok_or(-3)?;
    let to = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;

    let spender = context::msg_sender();
    if spender != from {
        let ak = allowance_key(&from, &spender);
        let allowed = storage::get_u64(ak.as_slice());
        if allowed < amount {
            return Err(-17); // insufficient allowance
        }
        storage::set_u64(ak.as_slice(), allowed - amount);
    }

    move_balance(&from, &to, amount)?;
    ret::write_bool(true);
    Ok(())
}

fn handle_balance_of(args: &CalldataReader) -> Result<(), i32> {
    let holder = args.address(0).ok_or(-3)?;
    let bk = balance_key(&holder);
    ret::write_u64_word(storage::get_u64(bk.as_slice()));
    Ok(())
}

fn handle_allowance(args: &CalldataReader) -> Result<(), i32> {
    let owner = args.address(0).ok_or(-3)?;
    let spender = args.address(1).ok_or(-3)?;
    let ak = allowance_key(&owner, &spender);
    ret::write_u64_word(storage::get_u64(ak.as_slice()));
    Ok(())
}

fn handle_total_supply(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_SUPPLY));
    Ok(())
}

fn handle_decimals(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_DECIMALS));
    Ok(())
}

fn handle_issuer(_args: &CalldataReader) -> Result<(), i32> {
    let issuer = storage::get_address(KEY_ISSUER).unwrap_or([0u8; 20]);
    ret::write_address(&issuer);
    Ok(())
}

fn handle_symbol(_args: &CalldataReader) -> Result<(), i32> {
    match storage::get_ref(KEY_SYMBOL) {
        Some(sym) => ret::write_abi_bytes(sym),
        None => ret::write_abi_bytes(&[]),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    fn init_cd(issuer: [u8; 20], sym: &[u8], dec: u64) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("initialize(address,string,uint64)"));
        let mut iw = [0u8; 32];
        iw[12..32].copy_from_slice(&issuer);
        cd.extend_from_slice(&iw);
        let mut off = [0u8; 32];
        off[31] = 0x60;
        cd.extend_from_slice(&off);
        let mut dw = [0u8; 32];
        dw[24..32].copy_from_slice(&dec.to_be_bytes());
        cd.extend_from_slice(&dw);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(sym.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(sym);
        cd.resize(cd.len() + (32 - sym.len() % 32) % 32, 0);
        cd
    }

    #[test]
    fn mint_approve_and_transfer_from_between_identities() {
        mock::reset();
        let ledger = [0x10; 20];
        let issuer = [0x01; 20];
        let alice_id = [0xA1; 20];
        let bob_id = [0xB2; 20];
        let otc = [0xCC; 20];
        mock::register_hps(ledger, dispatch_calldata);

        mock::transact_as(issuer, ledger, &init_cd(issuer, b"USD", 2)).unwrap();

        // Mint 1,000 USD to alice_id
        let mint_cd = CallEncoder::<128>::new(selector("mint(address,uint64)"))
            .push_address(&alice_id)
            .push_u64(1_000);
        mock::transact_as(issuer, ledger, mint_cd.as_slice()).unwrap();

        // Unauthorized spender fails
        let tf_cd = CallEncoder::<128>::new(selector("transferFrom(address,address,uint64)"))
            .push_address(&alice_id)
            .push_address(&bob_id)
            .push_u64(400);
        assert_eq!(mock::transact_as(otc, ledger, tf_cd.as_slice()), Err(-17));

        // Alice Identity approves OTC for 600 USD
        let app_cd = CallEncoder::<128>::new(selector("approve(address,uint64)"))
            .push_address(&otc)
            .push_u64(600);
        mock::transact_as(alice_id, ledger, app_cd.as_slice()).unwrap();

        // OTC executes transferFrom(alice_id, bob_id, 400)
        mock::transact_as(otc, ledger, tf_cd.as_slice()).unwrap();

        // Verify balances and remaining allowance (200)
        let bal_alice = mock::transact_as(
            issuer,
            ledger,
            CallEncoder::<64>::new(selector("balanceOf(address)"))
                .push_address(&alice_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&bal_alice[24..32], &600u64.to_be_bytes());

        let bal_bob = mock::transact_as(
            issuer,
            ledger,
            CallEncoder::<64>::new(selector("balanceOf(address)"))
                .push_address(&bob_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&bal_bob[24..32], &400u64.to_be_bytes());

        let rem_alw = mock::transact_as(
            issuer,
            ledger,
            CallEncoder::<96>::new(selector("allowance(address,address)"))
                .push_address(&alice_id)
                .push_address(&otc)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&rem_alw[24..32], &200u64.to_be_bytes());
    }
}
