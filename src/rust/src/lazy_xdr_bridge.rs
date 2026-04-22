// Auto-generated CXX bridge module for lazy XDR types.
// Do not edit manually.
//
// This module lives inside the stellar-core crate and bridges
// lazy XDR types from the stellar-xdr crate to C++ via CXX.
//
// We use #[repr(transparent)] newtype wrappers around each foreign
// lazy type so that CXX can implement its traits on local types.
// The #[cxx_name] attribute keeps the C++ names clean.

#![allow(clippy::boxed_local)]
#![allow(dead_code)]

extern crate alloc;
use alloc::sync::Arc;

// --- Newtype wrappers ---

#[repr(transparent)]
pub struct LazyScValW(stellar_xdr::LazyScVal);
pub struct LazyScValVecW(Vec<stellar_xdr::LazyScVal>);

#[repr(transparent)]
pub struct LazyLedgerEntryW(stellar_xdr::LazyLedgerEntry);
pub struct LazyLedgerEntryVecW(Vec<stellar_xdr::LazyLedgerEntry>);

#[repr(transparent)]
pub struct LazyLedgerKeyW(stellar_xdr::LazyLedgerKey);
pub struct LazyLedgerKeyVecW(Vec<stellar_xdr::LazyLedgerKey>);

#[repr(transparent)]
pub struct LazyHostFunctionW(stellar_xdr::LazyHostFunction);
pub struct LazyHostFunctionVecW(Vec<stellar_xdr::LazyHostFunction>);

#[repr(transparent)]
pub struct LazySorobanAuthorizationEntryW(stellar_xdr::LazySorobanAuthorizationEntry);
pub struct LazySorobanAuthorizationEntryVecW(Vec<stellar_xdr::LazySorobanAuthorizationEntry>);

#[repr(transparent)]
pub struct LazyScErrorW(stellar_xdr::LazyScError);

#[repr(transparent)]
pub struct LazyTimePointW(stellar_xdr::LazyTimePoint);

#[repr(transparent)]
pub struct LazyDurationW(stellar_xdr::LazyDuration);

#[repr(transparent)]
pub struct LazyUInt128PartsW(stellar_xdr::LazyUInt128Parts);

#[repr(transparent)]
pub struct LazyInt128PartsW(stellar_xdr::LazyInt128Parts);

#[repr(transparent)]
pub struct LazyUInt256PartsW(stellar_xdr::LazyUInt256Parts);

#[repr(transparent)]
pub struct LazyInt256PartsW(stellar_xdr::LazyInt256Parts);

#[repr(transparent)]
pub struct LazyScBytesW(stellar_xdr::LazyScBytes);

#[repr(transparent)]
pub struct LazyScStringW(stellar_xdr::LazyScString);

#[repr(transparent)]
pub struct LazyScSymbolW(stellar_xdr::LazyScSymbol);

#[repr(transparent)]
pub struct LazyScAddressW(stellar_xdr::LazyScAddress);

#[repr(transparent)]
pub struct LazyScContractInstanceW(stellar_xdr::LazyScContractInstance);

#[repr(transparent)]
pub struct LazyScNonceKeyW(stellar_xdr::LazyScNonceKey);

#[repr(transparent)]
pub struct LazyLedgerEntryDataW(stellar_xdr::LazyLedgerEntryData);

#[repr(transparent)]
pub struct LazyLedgerEntryExtW(stellar_xdr::LazyLedgerEntryExt);

#[repr(transparent)]
pub struct LazyLedgerKeyAccountW(stellar_xdr::LazyLedgerKeyAccount);

#[repr(transparent)]
pub struct LazyLedgerKeyTrustLineW(stellar_xdr::LazyLedgerKeyTrustLine);

#[repr(transparent)]
pub struct LazyLedgerKeyOfferW(stellar_xdr::LazyLedgerKeyOffer);

#[repr(transparent)]
pub struct LazyLedgerKeyDataW(stellar_xdr::LazyLedgerKeyData);

#[repr(transparent)]
pub struct LazyLedgerKeyClaimableBalanceW(stellar_xdr::LazyLedgerKeyClaimableBalance);

#[repr(transparent)]
pub struct LazyLedgerKeyLiquidityPoolW(stellar_xdr::LazyLedgerKeyLiquidityPool);

#[repr(transparent)]
pub struct LazyLedgerKeyContractDataW(stellar_xdr::LazyLedgerKeyContractData);

#[repr(transparent)]
pub struct LazyLedgerKeyContractCodeW(stellar_xdr::LazyLedgerKeyContractCode);

#[repr(transparent)]
pub struct LazyLedgerKeyConfigSettingW(stellar_xdr::LazyLedgerKeyConfigSetting);

#[repr(transparent)]
pub struct LazyLedgerKeyTtlW(stellar_xdr::LazyLedgerKeyTtl);

#[repr(transparent)]
pub struct LazyInvokeContractArgsW(stellar_xdr::LazyInvokeContractArgs);

#[repr(transparent)]
pub struct LazyCreateContractArgsW(stellar_xdr::LazyCreateContractArgs);

#[repr(transparent)]
pub struct LazyBytesMW(stellar_xdr::LazyBytesM);

#[repr(transparent)]
pub struct LazyCreateContractArgsV2W(stellar_xdr::LazyCreateContractArgsV2);

#[repr(transparent)]
pub struct LazySorobanCredentialsW(stellar_xdr::LazySorobanCredentials);

#[repr(transparent)]
pub struct LazySorobanAuthorizedInvocationW(stellar_xdr::LazySorobanAuthorizedInvocation);

// --- Free functions ---

fn new_lazy_sc_val(buf: &[u8]) -> Result<Box<LazyScValW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyScValW(stellar_xdr::LazyScVal::try_from(arc)?)))
}
fn lazy_sc_val_xdr_bytes(h: &LazyScValW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazy_sc_val_clone(h: &LazyScValW) -> Box<LazyScValW> {
    Box::new(LazyScValW(h.0.clone()))
}
fn lazy_sc_val_discriminant(h: &LazyScValW) -> i32 {
    h.0.discriminant_i32()
}
fn lazy_sc_val_as_bool(h: &LazyScValW) -> Result<bool, stellar_xdr::Error> {
    h.0.as_bool().ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_error(h: &LazyScValW) -> Result<Box<LazyScErrorW>, stellar_xdr::Error> {
    h.0.as_error()
        .map(|v| Box::new(LazyScErrorW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_u32(h: &LazyScValW) -> Result<u32, stellar_xdr::Error> {
    h.0.as_u32().ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_i32(h: &LazyScValW) -> Result<i32, stellar_xdr::Error> {
    h.0.as_i32().ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_u64(h: &LazyScValW) -> Result<u64, stellar_xdr::Error> {
    h.0.as_u64().ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_i64(h: &LazyScValW) -> Result<i64, stellar_xdr::Error> {
    h.0.as_i64().ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_timepoint(h: &LazyScValW) -> Result<Box<LazyTimePointW>, stellar_xdr::Error> {
    h.0.as_timepoint()
        .map(|v| Box::new(LazyTimePointW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_duration(h: &LazyScValW) -> Result<Box<LazyDurationW>, stellar_xdr::Error> {
    h.0.as_duration()
        .map(|v| Box::new(LazyDurationW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_u128(h: &LazyScValW) -> Result<Box<LazyUInt128PartsW>, stellar_xdr::Error> {
    h.0.as_u128()
        .map(|v| Box::new(LazyUInt128PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_i128(h: &LazyScValW) -> Result<Box<LazyInt128PartsW>, stellar_xdr::Error> {
    h.0.as_i128()
        .map(|v| Box::new(LazyInt128PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_u256(h: &LazyScValW) -> Result<Box<LazyUInt256PartsW>, stellar_xdr::Error> {
    h.0.as_u256()
        .map(|v| Box::new(LazyUInt256PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_i256(h: &LazyScValW) -> Result<Box<LazyInt256PartsW>, stellar_xdr::Error> {
    h.0.as_i256()
        .map(|v| Box::new(LazyInt256PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_bytes(h: &LazyScValW) -> Result<Box<LazyScBytesW>, stellar_xdr::Error> {
    h.0.as_bytes()
        .map(|v| Box::new(LazyScBytesW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_string(h: &LazyScValW) -> Result<Box<LazyScStringW>, stellar_xdr::Error> {
    h.0.as_string()
        .map(|v| Box::new(LazyScStringW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_symbol(h: &LazyScValW) -> Result<Box<LazyScSymbolW>, stellar_xdr::Error> {
    h.0.as_symbol()
        .map(|v| Box::new(LazyScSymbolW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_address(h: &LazyScValW) -> Result<Box<LazyScAddressW>, stellar_xdr::Error> {
    h.0.as_address()
        .map(|v| Box::new(LazyScAddressW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_contract_instance(
    h: &LazyScValW,
) -> Result<Box<LazyScContractInstanceW>, stellar_xdr::Error> {
    h.0.as_contract_instance()
        .map(|v| Box::new(LazyScContractInstanceW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_sc_val_as_ledger_key_nonce(
    h: &LazyScValW,
) -> Result<Box<LazyScNonceKeyW>, stellar_xdr::Error> {
    h.0.as_ledger_key_nonce()
        .map(|v| Box::new(LazyScNonceKeyW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

fn new_lazy_sc_val_vec() -> Box<LazyScValVecW> {
    Box::new(LazyScValVecW(Vec::new()))
}
impl LazyScValVecW {
    fn push(&mut self, h: Box<LazyScValW>) {
        self.0.push(h.0);
    }
    fn pop(&mut self) -> Result<Box<LazyScValW>, stellar_xdr::Error> {
        self.0
            .pop()
            .map(|v| Box::new(LazyScValW(v)))
            .ok_or(stellar_xdr::Error::Invalid)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Box<LazyScValW> {
        Box::new(LazyScValW(self.0[i].clone()))
    }
}

fn new_lazy_ledger_entry(buf: &[u8]) -> Result<Box<LazyLedgerEntryW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyLedgerEntryW(
        stellar_xdr::LazyLedgerEntry::try_from(arc)?,
    )))
}
fn lazy_ledger_entry_xdr_bytes(h: &LazyLedgerEntryW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazy_ledger_entry_clone(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryW> {
    Box::new(LazyLedgerEntryW(h.0.clone()))
}
fn lazy_ledger_entry_last_modified_ledger_seq(h: &LazyLedgerEntryW) -> u32 {
    h.0.last_modified_ledger_seq()
}
fn lazy_ledger_entry_data(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryDataW> {
    Box::new(LazyLedgerEntryDataW(h.0.data()))
}
fn lazy_ledger_entry_ext(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryExtW> {
    Box::new(LazyLedgerEntryExtW(h.0.ext()))
}

fn new_lazy_ledger_entry_vec() -> Box<LazyLedgerEntryVecW> {
    Box::new(LazyLedgerEntryVecW(Vec::new()))
}
impl LazyLedgerEntryVecW {
    fn push(&mut self, h: Box<LazyLedgerEntryW>) {
        self.0.push(h.0);
    }
    fn pop(&mut self) -> Result<Box<LazyLedgerEntryW>, stellar_xdr::Error> {
        self.0
            .pop()
            .map(|v| Box::new(LazyLedgerEntryW(v)))
            .ok_or(stellar_xdr::Error::Invalid)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Box<LazyLedgerEntryW> {
        Box::new(LazyLedgerEntryW(self.0[i].clone()))
    }
}

fn new_lazy_ledger_key(buf: &[u8]) -> Result<Box<LazyLedgerKeyW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyLedgerKeyW(
        stellar_xdr::LazyLedgerKey::try_from(arc)?,
    )))
}
fn lazy_ledger_key_xdr_bytes(h: &LazyLedgerKeyW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazy_ledger_key_clone(h: &LazyLedgerKeyW) -> Box<LazyLedgerKeyW> {
    Box::new(LazyLedgerKeyW(h.0.clone()))
}
fn lazy_ledger_key_discriminant(h: &LazyLedgerKeyW) -> i32 {
    h.0.discriminant_i32()
}
fn lazy_ledger_key_as_account(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyAccountW>, stellar_xdr::Error> {
    h.0.as_account()
        .map(|v| Box::new(LazyLedgerKeyAccountW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_trustline(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyTrustLineW>, stellar_xdr::Error> {
    h.0.as_trustline()
        .map(|v| Box::new(LazyLedgerKeyTrustLineW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_offer(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyOfferW>, stellar_xdr::Error> {
    h.0.as_offer()
        .map(|v| Box::new(LazyLedgerKeyOfferW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_data(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyDataW>, stellar_xdr::Error> {
    h.0.as_data()
        .map(|v| Box::new(LazyLedgerKeyDataW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_claimable_balance(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyClaimableBalanceW>, stellar_xdr::Error> {
    h.0.as_claimable_balance()
        .map(|v| Box::new(LazyLedgerKeyClaimableBalanceW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_liquidity_pool(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyLiquidityPoolW>, stellar_xdr::Error> {
    h.0.as_liquidity_pool()
        .map(|v| Box::new(LazyLedgerKeyLiquidityPoolW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_contract_data(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyContractDataW>, stellar_xdr::Error> {
    h.0.as_contract_data()
        .map(|v| Box::new(LazyLedgerKeyContractDataW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_contract_code(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyContractCodeW>, stellar_xdr::Error> {
    h.0.as_contract_code()
        .map(|v| Box::new(LazyLedgerKeyContractCodeW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_config_setting(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyConfigSettingW>, stellar_xdr::Error> {
    h.0.as_config_setting()
        .map(|v| Box::new(LazyLedgerKeyConfigSettingW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_ledger_key_as_ttl(
    h: &LazyLedgerKeyW,
) -> Result<Box<LazyLedgerKeyTtlW>, stellar_xdr::Error> {
    h.0.as_ttl()
        .map(|v| Box::new(LazyLedgerKeyTtlW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

fn new_lazy_ledger_key_vec() -> Box<LazyLedgerKeyVecW> {
    Box::new(LazyLedgerKeyVecW(Vec::new()))
}
impl LazyLedgerKeyVecW {
    fn push(&mut self, h: Box<LazyLedgerKeyW>) {
        self.0.push(h.0);
    }
    fn pop(&mut self) -> Result<Box<LazyLedgerKeyW>, stellar_xdr::Error> {
        self.0
            .pop()
            .map(|v| Box::new(LazyLedgerKeyW(v)))
            .ok_or(stellar_xdr::Error::Invalid)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Box<LazyLedgerKeyW> {
        Box::new(LazyLedgerKeyW(self.0[i].clone()))
    }
}

fn new_lazy_host_function(buf: &[u8]) -> Result<Box<LazyHostFunctionW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyHostFunctionW(
        stellar_xdr::LazyHostFunction::try_from(arc)?,
    )))
}
fn lazy_host_function_xdr_bytes(h: &LazyHostFunctionW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazy_host_function_clone(h: &LazyHostFunctionW) -> Box<LazyHostFunctionW> {
    Box::new(LazyHostFunctionW(h.0.clone()))
}
fn lazy_host_function_discriminant(h: &LazyHostFunctionW) -> i32 {
    h.0.discriminant_i32()
}
fn lazy_host_function_as_invoke_contract(
    h: &LazyHostFunctionW,
) -> Result<Box<LazyInvokeContractArgsW>, stellar_xdr::Error> {
    h.0.as_invoke_contract()
        .map(|v| Box::new(LazyInvokeContractArgsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_host_function_as_create_contract(
    h: &LazyHostFunctionW,
) -> Result<Box<LazyCreateContractArgsW>, stellar_xdr::Error> {
    h.0.as_create_contract()
        .map(|v| Box::new(LazyCreateContractArgsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_host_function_as_upload_contract_wasm(
    h: &LazyHostFunctionW,
) -> Result<Box<LazyBytesMW>, stellar_xdr::Error> {
    h.0.as_upload_contract_wasm()
        .map(|v| Box::new(LazyBytesMW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazy_host_function_as_create_contract_v2(
    h: &LazyHostFunctionW,
) -> Result<Box<LazyCreateContractArgsV2W>, stellar_xdr::Error> {
    h.0.as_create_contract_v2()
        .map(|v| Box::new(LazyCreateContractArgsV2W(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

fn new_lazy_host_function_vec() -> Box<LazyHostFunctionVecW> {
    Box::new(LazyHostFunctionVecW(Vec::new()))
}
impl LazyHostFunctionVecW {
    fn push(&mut self, h: Box<LazyHostFunctionW>) {
        self.0.push(h.0);
    }
    fn pop(&mut self) -> Result<Box<LazyHostFunctionW>, stellar_xdr::Error> {
        self.0
            .pop()
            .map(|v| Box::new(LazyHostFunctionW(v)))
            .ok_or(stellar_xdr::Error::Invalid)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Box<LazyHostFunctionW> {
        Box::new(LazyHostFunctionW(self.0[i].clone()))
    }
}

fn new_lazy_soroban_authorization_entry(
    buf: &[u8],
) -> Result<Box<LazySorobanAuthorizationEntryW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazySorobanAuthorizationEntryW(
        stellar_xdr::LazySorobanAuthorizationEntry::try_from(arc)?,
    )))
}
fn lazy_soroban_authorization_entry_xdr_bytes(h: &LazySorobanAuthorizationEntryW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazy_soroban_authorization_entry_clone(
    h: &LazySorobanAuthorizationEntryW,
) -> Box<LazySorobanAuthorizationEntryW> {
    Box::new(LazySorobanAuthorizationEntryW(h.0.clone()))
}
fn lazy_soroban_authorization_entry_credentials(
    h: &LazySorobanAuthorizationEntryW,
) -> Box<LazySorobanCredentialsW> {
    Box::new(LazySorobanCredentialsW(h.0.credentials()))
}
fn lazy_soroban_authorization_entry_root_invocation(
    h: &LazySorobanAuthorizationEntryW,
) -> Box<LazySorobanAuthorizedInvocationW> {
    Box::new(LazySorobanAuthorizedInvocationW(h.0.root_invocation()))
}

fn new_lazy_soroban_authorization_entry_vec() -> Box<LazySorobanAuthorizationEntryVecW> {
    Box::new(LazySorobanAuthorizationEntryVecW(Vec::new()))
}
impl LazySorobanAuthorizationEntryVecW {
    fn push(&mut self, h: Box<LazySorobanAuthorizationEntryW>) {
        self.0.push(h.0);
    }
    fn pop(&mut self) -> Result<Box<LazySorobanAuthorizationEntryW>, stellar_xdr::Error> {
        self.0
            .pop()
            .map(|v| Box::new(LazySorobanAuthorizationEntryW(v)))
            .ok_or(stellar_xdr::Error::Invalid)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Box<LazySorobanAuthorizationEntryW> {
        Box::new(LazySorobanAuthorizationEntryW(self.0[i].clone()))
    }
}

// --- CXX bridge declaration ---
#[cxx::bridge(namespace = "stellar::lazy_xdr")]
mod ffi {
    extern "Rust" {

        #[cxx_name = "LazyScVal"]
        type LazyScValW;
        fn new_lazy_sc_val(buf: &[u8]) -> Result<Box<LazyScValW>>;
        fn lazy_sc_val_xdr_bytes(h: &LazyScValW) -> &[u8];
        fn lazy_sc_val_clone(h: &LazyScValW) -> Box<LazyScValW>;
        fn lazy_sc_val_discriminant(h: &LazyScValW) -> i32;
        fn lazy_sc_val_as_bool(h: &LazyScValW) -> Result<bool>;
        fn lazy_sc_val_as_error(h: &LazyScValW) -> Result<Box<LazyScErrorW>>;
        fn lazy_sc_val_as_u32(h: &LazyScValW) -> Result<u32>;
        fn lazy_sc_val_as_i32(h: &LazyScValW) -> Result<i32>;
        fn lazy_sc_val_as_u64(h: &LazyScValW) -> Result<u64>;
        fn lazy_sc_val_as_i64(h: &LazyScValW) -> Result<i64>;
        fn lazy_sc_val_as_timepoint(h: &LazyScValW) -> Result<Box<LazyTimePointW>>;
        fn lazy_sc_val_as_duration(h: &LazyScValW) -> Result<Box<LazyDurationW>>;
        fn lazy_sc_val_as_u128(h: &LazyScValW) -> Result<Box<LazyUInt128PartsW>>;
        fn lazy_sc_val_as_i128(h: &LazyScValW) -> Result<Box<LazyInt128PartsW>>;
        fn lazy_sc_val_as_u256(h: &LazyScValW) -> Result<Box<LazyUInt256PartsW>>;
        fn lazy_sc_val_as_i256(h: &LazyScValW) -> Result<Box<LazyInt256PartsW>>;
        fn lazy_sc_val_as_bytes(h: &LazyScValW) -> Result<Box<LazyScBytesW>>;
        fn lazy_sc_val_as_string(h: &LazyScValW) -> Result<Box<LazyScStringW>>;
        fn lazy_sc_val_as_symbol(h: &LazyScValW) -> Result<Box<LazyScSymbolW>>;
        fn lazy_sc_val_as_address(h: &LazyScValW) -> Result<Box<LazyScAddressW>>;
        fn lazy_sc_val_as_contract_instance(h: &LazyScValW)
            -> Result<Box<LazyScContractInstanceW>>;
        fn lazy_sc_val_as_ledger_key_nonce(h: &LazyScValW) -> Result<Box<LazyScNonceKeyW>>;

        #[cxx_name = "LazyScValVec"]
        type LazyScValVecW;
        fn new_lazy_sc_val_vec() -> Box<LazyScValVecW>;
        fn push(self: &mut LazyScValVecW, h: Box<LazyScValW>);
        fn pop(self: &mut LazyScValVecW) -> Result<Box<LazyScValW>>;
        fn len(self: &LazyScValVecW) -> usize;
        fn get(self: &LazyScValVecW, i: usize) -> Box<LazyScValW>;

        #[cxx_name = "LazyLedgerEntry"]
        type LazyLedgerEntryW;
        fn new_lazy_ledger_entry(buf: &[u8]) -> Result<Box<LazyLedgerEntryW>>;
        fn lazy_ledger_entry_xdr_bytes(h: &LazyLedgerEntryW) -> &[u8];
        fn lazy_ledger_entry_clone(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryW>;
        fn lazy_ledger_entry_last_modified_ledger_seq(h: &LazyLedgerEntryW) -> u32;
        fn lazy_ledger_entry_data(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryDataW>;
        fn lazy_ledger_entry_ext(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryExtW>;

        #[cxx_name = "LazyLedgerEntryVec"]
        type LazyLedgerEntryVecW;
        fn new_lazy_ledger_entry_vec() -> Box<LazyLedgerEntryVecW>;
        fn push(self: &mut LazyLedgerEntryVecW, h: Box<LazyLedgerEntryW>);
        fn pop(self: &mut LazyLedgerEntryVecW) -> Result<Box<LazyLedgerEntryW>>;
        fn len(self: &LazyLedgerEntryVecW) -> usize;
        fn get(self: &LazyLedgerEntryVecW, i: usize) -> Box<LazyLedgerEntryW>;

        #[cxx_name = "LazyLedgerKey"]
        type LazyLedgerKeyW;
        fn new_lazy_ledger_key(buf: &[u8]) -> Result<Box<LazyLedgerKeyW>>;
        fn lazy_ledger_key_xdr_bytes(h: &LazyLedgerKeyW) -> &[u8];
        fn lazy_ledger_key_clone(h: &LazyLedgerKeyW) -> Box<LazyLedgerKeyW>;
        fn lazy_ledger_key_discriminant(h: &LazyLedgerKeyW) -> i32;
        fn lazy_ledger_key_as_account(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyAccountW>>;
        fn lazy_ledger_key_as_trustline(h: &LazyLedgerKeyW)
            -> Result<Box<LazyLedgerKeyTrustLineW>>;
        fn lazy_ledger_key_as_offer(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyOfferW>>;
        fn lazy_ledger_key_as_data(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyDataW>>;
        fn lazy_ledger_key_as_claimable_balance(
            h: &LazyLedgerKeyW,
        ) -> Result<Box<LazyLedgerKeyClaimableBalanceW>>;
        fn lazy_ledger_key_as_liquidity_pool(
            h: &LazyLedgerKeyW,
        ) -> Result<Box<LazyLedgerKeyLiquidityPoolW>>;
        fn lazy_ledger_key_as_contract_data(
            h: &LazyLedgerKeyW,
        ) -> Result<Box<LazyLedgerKeyContractDataW>>;
        fn lazy_ledger_key_as_contract_code(
            h: &LazyLedgerKeyW,
        ) -> Result<Box<LazyLedgerKeyContractCodeW>>;
        fn lazy_ledger_key_as_config_setting(
            h: &LazyLedgerKeyW,
        ) -> Result<Box<LazyLedgerKeyConfigSettingW>>;
        fn lazy_ledger_key_as_ttl(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyTtlW>>;

        #[cxx_name = "LazyLedgerKeyVec"]
        type LazyLedgerKeyVecW;
        fn new_lazy_ledger_key_vec() -> Box<LazyLedgerKeyVecW>;
        fn push(self: &mut LazyLedgerKeyVecW, h: Box<LazyLedgerKeyW>);
        fn pop(self: &mut LazyLedgerKeyVecW) -> Result<Box<LazyLedgerKeyW>>;
        fn len(self: &LazyLedgerKeyVecW) -> usize;
        fn get(self: &LazyLedgerKeyVecW, i: usize) -> Box<LazyLedgerKeyW>;

        #[cxx_name = "LazyHostFunction"]
        type LazyHostFunctionW;
        fn new_lazy_host_function(buf: &[u8]) -> Result<Box<LazyHostFunctionW>>;
        fn lazy_host_function_xdr_bytes(h: &LazyHostFunctionW) -> &[u8];
        fn lazy_host_function_clone(h: &LazyHostFunctionW) -> Box<LazyHostFunctionW>;
        fn lazy_host_function_discriminant(h: &LazyHostFunctionW) -> i32;
        fn lazy_host_function_as_invoke_contract(
            h: &LazyHostFunctionW,
        ) -> Result<Box<LazyInvokeContractArgsW>>;
        fn lazy_host_function_as_create_contract(
            h: &LazyHostFunctionW,
        ) -> Result<Box<LazyCreateContractArgsW>>;
        fn lazy_host_function_as_upload_contract_wasm(
            h: &LazyHostFunctionW,
        ) -> Result<Box<LazyBytesMW>>;
        fn lazy_host_function_as_create_contract_v2(
            h: &LazyHostFunctionW,
        ) -> Result<Box<LazyCreateContractArgsV2W>>;

        #[cxx_name = "LazyHostFunctionVec"]
        type LazyHostFunctionVecW;
        fn new_lazy_host_function_vec() -> Box<LazyHostFunctionVecW>;
        fn push(self: &mut LazyHostFunctionVecW, h: Box<LazyHostFunctionW>);
        fn pop(self: &mut LazyHostFunctionVecW) -> Result<Box<LazyHostFunctionW>>;
        fn len(self: &LazyHostFunctionVecW) -> usize;
        fn get(self: &LazyHostFunctionVecW, i: usize) -> Box<LazyHostFunctionW>;

        #[cxx_name = "LazySorobanAuthorizationEntry"]
        type LazySorobanAuthorizationEntryW;
        fn new_lazy_soroban_authorization_entry(
            buf: &[u8],
        ) -> Result<Box<LazySorobanAuthorizationEntryW>>;
        fn lazy_soroban_authorization_entry_xdr_bytes(h: &LazySorobanAuthorizationEntryW) -> &[u8];
        fn lazy_soroban_authorization_entry_clone(
            h: &LazySorobanAuthorizationEntryW,
        ) -> Box<LazySorobanAuthorizationEntryW>;
        fn lazy_soroban_authorization_entry_credentials(
            h: &LazySorobanAuthorizationEntryW,
        ) -> Box<LazySorobanCredentialsW>;
        fn lazy_soroban_authorization_entry_root_invocation(
            h: &LazySorobanAuthorizationEntryW,
        ) -> Box<LazySorobanAuthorizedInvocationW>;

        #[cxx_name = "LazySorobanAuthorizationEntryVec"]
        type LazySorobanAuthorizationEntryVecW;
        fn new_lazy_soroban_authorization_entry_vec() -> Box<LazySorobanAuthorizationEntryVecW>;
        fn push(
            self: &mut LazySorobanAuthorizationEntryVecW,
            h: Box<LazySorobanAuthorizationEntryW>,
        );
        fn pop(
            self: &mut LazySorobanAuthorizationEntryVecW,
        ) -> Result<Box<LazySorobanAuthorizationEntryW>>;
        fn len(self: &LazySorobanAuthorizationEntryVecW) -> usize;
        fn get(
            self: &LazySorobanAuthorizationEntryVecW,
            i: usize,
        ) -> Box<LazySorobanAuthorizationEntryW>;

        #[cxx_name = "LazyScError"]
        type LazyScErrorW;

        #[cxx_name = "LazyTimePoint"]
        type LazyTimePointW;

        #[cxx_name = "LazyDuration"]
        type LazyDurationW;

        #[cxx_name = "LazyUInt128Parts"]
        type LazyUInt128PartsW;

        #[cxx_name = "LazyInt128Parts"]
        type LazyInt128PartsW;

        #[cxx_name = "LazyUInt256Parts"]
        type LazyUInt256PartsW;

        #[cxx_name = "LazyInt256Parts"]
        type LazyInt256PartsW;

        #[cxx_name = "LazyScBytes"]
        type LazyScBytesW;

        #[cxx_name = "LazyScString"]
        type LazyScStringW;

        #[cxx_name = "LazyScSymbol"]
        type LazyScSymbolW;

        #[cxx_name = "LazyScAddress"]
        type LazyScAddressW;

        #[cxx_name = "LazyScContractInstance"]
        type LazyScContractInstanceW;

        #[cxx_name = "LazyScNonceKey"]
        type LazyScNonceKeyW;

        #[cxx_name = "LazyLedgerEntryData"]
        type LazyLedgerEntryDataW;

        #[cxx_name = "LazyLedgerEntryExt"]
        type LazyLedgerEntryExtW;

        #[cxx_name = "LazyLedgerKeyAccount"]
        type LazyLedgerKeyAccountW;

        #[cxx_name = "LazyLedgerKeyTrustLine"]
        type LazyLedgerKeyTrustLineW;

        #[cxx_name = "LazyLedgerKeyOffer"]
        type LazyLedgerKeyOfferW;

        #[cxx_name = "LazyLedgerKeyData"]
        type LazyLedgerKeyDataW;

        #[cxx_name = "LazyLedgerKeyClaimableBalance"]
        type LazyLedgerKeyClaimableBalanceW;

        #[cxx_name = "LazyLedgerKeyLiquidityPool"]
        type LazyLedgerKeyLiquidityPoolW;

        #[cxx_name = "LazyLedgerKeyContractData"]
        type LazyLedgerKeyContractDataW;

        #[cxx_name = "LazyLedgerKeyContractCode"]
        type LazyLedgerKeyContractCodeW;

        #[cxx_name = "LazyLedgerKeyConfigSetting"]
        type LazyLedgerKeyConfigSettingW;

        #[cxx_name = "LazyLedgerKeyTtl"]
        type LazyLedgerKeyTtlW;

        #[cxx_name = "LazyInvokeContractArgs"]
        type LazyInvokeContractArgsW;

        #[cxx_name = "LazyCreateContractArgs"]
        type LazyCreateContractArgsW;

        #[cxx_name = "LazyBytesM"]
        type LazyBytesMW;

        #[cxx_name = "LazyCreateContractArgsV2"]
        type LazyCreateContractArgsV2W;

        #[cxx_name = "LazySorobanCredentials"]
        type LazySorobanCredentialsW;

        #[cxx_name = "LazySorobanAuthorizedInvocation"]
        type LazySorobanAuthorizedInvocationW;
    }
}
