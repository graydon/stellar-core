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

#[repr(transparent)]
pub struct LazyLedgerEntryW(stellar_xdr::LazyLedgerEntry);

#[repr(transparent)]
pub struct LazyLedgerKeyW(stellar_xdr::LazyLedgerKey);

#[repr(transparent)]
pub struct LazyHostFunctionW(stellar_xdr::LazyHostFunction);

#[repr(transparent)]
pub struct LazySorobanAuthorizationEntryW(stellar_xdr::LazySorobanAuthorizationEntry);

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

// --- Free functions (implementations) ---

// LazyScVal
fn new_lazyscval(buf: &[u8]) -> Result<Box<LazyScValW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyScValW(stellar_xdr::LazyScVal::try_from(arc)?)))
}
fn lazyscval_xdr_bytes(h: &LazyScValW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazyscval_clone(h: &LazyScValW) -> Box<LazyScValW> {
    Box::new(LazyScValW(h.0.clone()))
}
fn lazyscval_discriminant(h: &LazyScValW) -> i32 {
    h.0.discriminant_i32()
}
fn lazyscval_as_bool(h: &LazyScValW) -> Result<bool, stellar_xdr::Error> {
    h.0.as_bool()
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_error(h: &LazyScValW) -> Result<Box<LazyScErrorW>, stellar_xdr::Error> {
    h.0.as_error()
        .map(|v| Box::new(LazyScErrorW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_u32(h: &LazyScValW) -> Result<u32, stellar_xdr::Error> {
    h.0.as_u32()
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_i32(h: &LazyScValW) -> Result<i32, stellar_xdr::Error> {
    h.0.as_i32()
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_u64(h: &LazyScValW) -> Result<u64, stellar_xdr::Error> {
    h.0.as_u64()
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_i64(h: &LazyScValW) -> Result<i64, stellar_xdr::Error> {
    h.0.as_i64()
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_timepoint(h: &LazyScValW) -> Result<Box<LazyTimePointW>, stellar_xdr::Error> {
    h.0.as_timepoint()
        .map(|v| Box::new(LazyTimePointW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_duration(h: &LazyScValW) -> Result<Box<LazyDurationW>, stellar_xdr::Error> {
    h.0.as_duration()
        .map(|v| Box::new(LazyDurationW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_u128(h: &LazyScValW) -> Result<Box<LazyUInt128PartsW>, stellar_xdr::Error> {
    h.0.as_u128()
        .map(|v| Box::new(LazyUInt128PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_i128(h: &LazyScValW) -> Result<Box<LazyInt128PartsW>, stellar_xdr::Error> {
    h.0.as_i128()
        .map(|v| Box::new(LazyInt128PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_u256(h: &LazyScValW) -> Result<Box<LazyUInt256PartsW>, stellar_xdr::Error> {
    h.0.as_u256()
        .map(|v| Box::new(LazyUInt256PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_i256(h: &LazyScValW) -> Result<Box<LazyInt256PartsW>, stellar_xdr::Error> {
    h.0.as_i256()
        .map(|v| Box::new(LazyInt256PartsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_bytes(h: &LazyScValW) -> Result<Box<LazyScBytesW>, stellar_xdr::Error> {
    h.0.as_bytes()
        .map(|v| Box::new(LazyScBytesW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_string(h: &LazyScValW) -> Result<Box<LazyScStringW>, stellar_xdr::Error> {
    h.0.as_string()
        .map(|v| Box::new(LazyScStringW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_symbol(h: &LazyScValW) -> Result<Box<LazyScSymbolW>, stellar_xdr::Error> {
    h.0.as_symbol()
        .map(|v| Box::new(LazyScSymbolW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_address(h: &LazyScValW) -> Result<Box<LazyScAddressW>, stellar_xdr::Error> {
    h.0.as_address()
        .map(|v| Box::new(LazyScAddressW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_contract_instance(h: &LazyScValW) -> Result<Box<LazyScContractInstanceW>, stellar_xdr::Error> {
    h.0.as_contract_instance()
        .map(|v| Box::new(LazyScContractInstanceW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyscval_as_ledger_key_nonce(h: &LazyScValW) -> Result<Box<LazyScNonceKeyW>, stellar_xdr::Error> {
    h.0.as_ledger_key_nonce()
        .map(|v| Box::new(LazyScNonceKeyW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

// LazyLedgerEntry
fn new_lazyledgerentry(buf: &[u8]) -> Result<Box<LazyLedgerEntryW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyLedgerEntryW(stellar_xdr::LazyLedgerEntry::try_from(arc)?)))
}
fn lazyledgerentry_xdr_bytes(h: &LazyLedgerEntryW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazyledgerentry_clone(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryW> {
    Box::new(LazyLedgerEntryW(h.0.clone()))
}
fn lazyledgerentry_last_modified_ledger_seq(h: &LazyLedgerEntryW) -> u32 {
    h.0.last_modified_ledger_seq()
}
fn lazyledgerentry_data(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryDataW> {
    Box::new(LazyLedgerEntryDataW(h.0.data()))
}
fn lazyledgerentry_ext(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryExtW> {
    Box::new(LazyLedgerEntryExtW(h.0.ext()))
}

// LazyLedgerKey
fn new_lazyledgerkey(buf: &[u8]) -> Result<Box<LazyLedgerKeyW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyLedgerKeyW(stellar_xdr::LazyLedgerKey::try_from(arc)?)))
}
fn lazyledgerkey_xdr_bytes(h: &LazyLedgerKeyW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazyledgerkey_clone(h: &LazyLedgerKeyW) -> Box<LazyLedgerKeyW> {
    Box::new(LazyLedgerKeyW(h.0.clone()))
}
fn lazyledgerkey_discriminant(h: &LazyLedgerKeyW) -> i32 {
    h.0.discriminant_i32()
}
fn lazyledgerkey_as_account(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyAccountW>, stellar_xdr::Error> {
    h.0.as_account()
        .map(|v| Box::new(LazyLedgerKeyAccountW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_trustline(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyTrustLineW>, stellar_xdr::Error> {
    h.0.as_trustline()
        .map(|v| Box::new(LazyLedgerKeyTrustLineW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_offer(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyOfferW>, stellar_xdr::Error> {
    h.0.as_offer()
        .map(|v| Box::new(LazyLedgerKeyOfferW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_data(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyDataW>, stellar_xdr::Error> {
    h.0.as_data()
        .map(|v| Box::new(LazyLedgerKeyDataW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_claimable_balance(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyClaimableBalanceW>, stellar_xdr::Error> {
    h.0.as_claimable_balance()
        .map(|v| Box::new(LazyLedgerKeyClaimableBalanceW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_liquidity_pool(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyLiquidityPoolW>, stellar_xdr::Error> {
    h.0.as_liquidity_pool()
        .map(|v| Box::new(LazyLedgerKeyLiquidityPoolW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_contract_data(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyContractDataW>, stellar_xdr::Error> {
    h.0.as_contract_data()
        .map(|v| Box::new(LazyLedgerKeyContractDataW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_contract_code(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyContractCodeW>, stellar_xdr::Error> {
    h.0.as_contract_code()
        .map(|v| Box::new(LazyLedgerKeyContractCodeW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_config_setting(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyConfigSettingW>, stellar_xdr::Error> {
    h.0.as_config_setting()
        .map(|v| Box::new(LazyLedgerKeyConfigSettingW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyledgerkey_as_ttl(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyTtlW>, stellar_xdr::Error> {
    h.0.as_ttl()
        .map(|v| Box::new(LazyLedgerKeyTtlW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

// LazyHostFunction
fn new_lazyhostfunction(buf: &[u8]) -> Result<Box<LazyHostFunctionW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazyHostFunctionW(stellar_xdr::LazyHostFunction::try_from(arc)?)))
}
fn lazyhostfunction_xdr_bytes(h: &LazyHostFunctionW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazyhostfunction_clone(h: &LazyHostFunctionW) -> Box<LazyHostFunctionW> {
    Box::new(LazyHostFunctionW(h.0.clone()))
}
fn lazyhostfunction_discriminant(h: &LazyHostFunctionW) -> i32 {
    h.0.discriminant_i32()
}
fn lazyhostfunction_as_invoke_contract(h: &LazyHostFunctionW) -> Result<Box<LazyInvokeContractArgsW>, stellar_xdr::Error> {
    h.0.as_invoke_contract()
        .map(|v| Box::new(LazyInvokeContractArgsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyhostfunction_as_create_contract(h: &LazyHostFunctionW) -> Result<Box<LazyCreateContractArgsW>, stellar_xdr::Error> {
    h.0.as_create_contract()
        .map(|v| Box::new(LazyCreateContractArgsW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyhostfunction_as_upload_contract_wasm(h: &LazyHostFunctionW) -> Result<Box<LazyBytesMW>, stellar_xdr::Error> {
    h.0.as_upload_contract_wasm()
        .map(|v| Box::new(LazyBytesMW(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}
fn lazyhostfunction_as_create_contract_v2(h: &LazyHostFunctionW) -> Result<Box<LazyCreateContractArgsV2W>, stellar_xdr::Error> {
    h.0.as_create_contract_v2()
        .map(|v| Box::new(LazyCreateContractArgsV2W(v)))
        .ok_or(stellar_xdr::Error::Invalid)
}

// LazySorobanAuthorizationEntry
fn new_lazysorobanauthorizationentry(buf: &[u8]) -> Result<Box<LazySorobanAuthorizationEntryW>, stellar_xdr::Error> {
    let arc: Arc<[u8]> = buf.into();
    Ok(Box::new(LazySorobanAuthorizationEntryW(stellar_xdr::LazySorobanAuthorizationEntry::try_from(arc)?)))
}
fn lazysorobanauthorizationentry_xdr_bytes(h: &LazySorobanAuthorizationEntryW) -> &[u8] {
    h.0.as_ref().as_slice()
}
fn lazysorobanauthorizationentry_clone(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanAuthorizationEntryW> {
    Box::new(LazySorobanAuthorizationEntryW(h.0.clone()))
}
fn lazysorobanauthorizationentry_credentials(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanCredentialsW> {
    Box::new(LazySorobanCredentialsW(h.0.credentials()))
}
fn lazysorobanauthorizationentry_root_invocation(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanAuthorizedInvocationW> {
    Box::new(LazySorobanAuthorizedInvocationW(h.0.root_invocation()))
}
































// --- CXX bridge module declaration ---
#[cxx::bridge(namespace = "stellar::lazy_xdr")]
mod ffi {
    extern "Rust" {

        // LazyScVal
        #[cxx_name = "LazyScVal"]
        type LazyScValW;
        fn new_lazyscval(buf: &[u8]) -> Result<Box<LazyScValW>>;
        fn lazyscval_xdr_bytes(h: &LazyScValW) -> &[u8];
        fn lazyscval_clone(h: &LazyScValW) -> Box<LazyScValW>;
        fn lazyscval_discriminant(h: &LazyScValW) -> i32;
        fn lazyscval_as_bool(h: &LazyScValW) -> Result<bool>;
        fn lazyscval_as_error(h: &LazyScValW) -> Result<Box<LazyScErrorW>>;
        fn lazyscval_as_u32(h: &LazyScValW) -> Result<u32>;
        fn lazyscval_as_i32(h: &LazyScValW) -> Result<i32>;
        fn lazyscval_as_u64(h: &LazyScValW) -> Result<u64>;
        fn lazyscval_as_i64(h: &LazyScValW) -> Result<i64>;
        fn lazyscval_as_timepoint(h: &LazyScValW) -> Result<Box<LazyTimePointW>>;
        fn lazyscval_as_duration(h: &LazyScValW) -> Result<Box<LazyDurationW>>;
        fn lazyscval_as_u128(h: &LazyScValW) -> Result<Box<LazyUInt128PartsW>>;
        fn lazyscval_as_i128(h: &LazyScValW) -> Result<Box<LazyInt128PartsW>>;
        fn lazyscval_as_u256(h: &LazyScValW) -> Result<Box<LazyUInt256PartsW>>;
        fn lazyscval_as_i256(h: &LazyScValW) -> Result<Box<LazyInt256PartsW>>;
        fn lazyscval_as_bytes(h: &LazyScValW) -> Result<Box<LazyScBytesW>>;
        fn lazyscval_as_string(h: &LazyScValW) -> Result<Box<LazyScStringW>>;
        fn lazyscval_as_symbol(h: &LazyScValW) -> Result<Box<LazyScSymbolW>>;
        fn lazyscval_as_address(h: &LazyScValW) -> Result<Box<LazyScAddressW>>;
        fn lazyscval_as_contract_instance(h: &LazyScValW) -> Result<Box<LazyScContractInstanceW>>;
        fn lazyscval_as_ledger_key_nonce(h: &LazyScValW) -> Result<Box<LazyScNonceKeyW>>;

        // LazyLedgerEntry
        #[cxx_name = "LazyLedgerEntry"]
        type LazyLedgerEntryW;
        fn new_lazyledgerentry(buf: &[u8]) -> Result<Box<LazyLedgerEntryW>>;
        fn lazyledgerentry_xdr_bytes(h: &LazyLedgerEntryW) -> &[u8];
        fn lazyledgerentry_clone(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryW>;
        fn lazyledgerentry_last_modified_ledger_seq(h: &LazyLedgerEntryW) -> u32;
        fn lazyledgerentry_data(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryDataW>;
        fn lazyledgerentry_ext(h: &LazyLedgerEntryW) -> Box<LazyLedgerEntryExtW>;

        // LazyLedgerKey
        #[cxx_name = "LazyLedgerKey"]
        type LazyLedgerKeyW;
        fn new_lazyledgerkey(buf: &[u8]) -> Result<Box<LazyLedgerKeyW>>;
        fn lazyledgerkey_xdr_bytes(h: &LazyLedgerKeyW) -> &[u8];
        fn lazyledgerkey_clone(h: &LazyLedgerKeyW) -> Box<LazyLedgerKeyW>;
        fn lazyledgerkey_discriminant(h: &LazyLedgerKeyW) -> i32;
        fn lazyledgerkey_as_account(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyAccountW>>;
        fn lazyledgerkey_as_trustline(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyTrustLineW>>;
        fn lazyledgerkey_as_offer(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyOfferW>>;
        fn lazyledgerkey_as_data(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyDataW>>;
        fn lazyledgerkey_as_claimable_balance(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyClaimableBalanceW>>;
        fn lazyledgerkey_as_liquidity_pool(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyLiquidityPoolW>>;
        fn lazyledgerkey_as_contract_data(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyContractDataW>>;
        fn lazyledgerkey_as_contract_code(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyContractCodeW>>;
        fn lazyledgerkey_as_config_setting(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyConfigSettingW>>;
        fn lazyledgerkey_as_ttl(h: &LazyLedgerKeyW) -> Result<Box<LazyLedgerKeyTtlW>>;

        // LazyHostFunction
        #[cxx_name = "LazyHostFunction"]
        type LazyHostFunctionW;
        fn new_lazyhostfunction(buf: &[u8]) -> Result<Box<LazyHostFunctionW>>;
        fn lazyhostfunction_xdr_bytes(h: &LazyHostFunctionW) -> &[u8];
        fn lazyhostfunction_clone(h: &LazyHostFunctionW) -> Box<LazyHostFunctionW>;
        fn lazyhostfunction_discriminant(h: &LazyHostFunctionW) -> i32;
        fn lazyhostfunction_as_invoke_contract(h: &LazyHostFunctionW) -> Result<Box<LazyInvokeContractArgsW>>;
        fn lazyhostfunction_as_create_contract(h: &LazyHostFunctionW) -> Result<Box<LazyCreateContractArgsW>>;
        fn lazyhostfunction_as_upload_contract_wasm(h: &LazyHostFunctionW) -> Result<Box<LazyBytesMW>>;
        fn lazyhostfunction_as_create_contract_v2(h: &LazyHostFunctionW) -> Result<Box<LazyCreateContractArgsV2W>>;

        // LazySorobanAuthorizationEntry
        #[cxx_name = "LazySorobanAuthorizationEntry"]
        type LazySorobanAuthorizationEntryW;
        fn new_lazysorobanauthorizationentry(buf: &[u8]) -> Result<Box<LazySorobanAuthorizationEntryW>>;
        fn lazysorobanauthorizationentry_xdr_bytes(h: &LazySorobanAuthorizationEntryW) -> &[u8];
        fn lazysorobanauthorizationentry_clone(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanAuthorizationEntryW>;
        fn lazysorobanauthorizationentry_credentials(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanCredentialsW>;
        fn lazysorobanauthorizationentry_root_invocation(h: &LazySorobanAuthorizationEntryW) -> Box<LazySorobanAuthorizedInvocationW>;

        // LazyScError (opaque only)
        #[cxx_name = "LazyScError"]
        type LazyScErrorW;

        // LazyTimePoint (opaque only)
        #[cxx_name = "LazyTimePoint"]
        type LazyTimePointW;

        // LazyDuration (opaque only)
        #[cxx_name = "LazyDuration"]
        type LazyDurationW;

        // LazyUInt128Parts (opaque only)
        #[cxx_name = "LazyUInt128Parts"]
        type LazyUInt128PartsW;

        // LazyInt128Parts (opaque only)
        #[cxx_name = "LazyInt128Parts"]
        type LazyInt128PartsW;

        // LazyUInt256Parts (opaque only)
        #[cxx_name = "LazyUInt256Parts"]
        type LazyUInt256PartsW;

        // LazyInt256Parts (opaque only)
        #[cxx_name = "LazyInt256Parts"]
        type LazyInt256PartsW;

        // LazyScBytes (opaque only)
        #[cxx_name = "LazyScBytes"]
        type LazyScBytesW;

        // LazyScString (opaque only)
        #[cxx_name = "LazyScString"]
        type LazyScStringW;

        // LazyScSymbol (opaque only)
        #[cxx_name = "LazyScSymbol"]
        type LazyScSymbolW;

        // LazyScAddress (opaque only)
        #[cxx_name = "LazyScAddress"]
        type LazyScAddressW;

        // LazyScContractInstance (opaque only)
        #[cxx_name = "LazyScContractInstance"]
        type LazyScContractInstanceW;

        // LazyScNonceKey (opaque only)
        #[cxx_name = "LazyScNonceKey"]
        type LazyScNonceKeyW;

        // LazyLedgerEntryData (opaque only)
        #[cxx_name = "LazyLedgerEntryData"]
        type LazyLedgerEntryDataW;

        // LazyLedgerEntryExt (opaque only)
        #[cxx_name = "LazyLedgerEntryExt"]
        type LazyLedgerEntryExtW;

        // LazyLedgerKeyAccount (opaque only)
        #[cxx_name = "LazyLedgerKeyAccount"]
        type LazyLedgerKeyAccountW;

        // LazyLedgerKeyTrustLine (opaque only)
        #[cxx_name = "LazyLedgerKeyTrustLine"]
        type LazyLedgerKeyTrustLineW;

        // LazyLedgerKeyOffer (opaque only)
        #[cxx_name = "LazyLedgerKeyOffer"]
        type LazyLedgerKeyOfferW;

        // LazyLedgerKeyData (opaque only)
        #[cxx_name = "LazyLedgerKeyData"]
        type LazyLedgerKeyDataW;

        // LazyLedgerKeyClaimableBalance (opaque only)
        #[cxx_name = "LazyLedgerKeyClaimableBalance"]
        type LazyLedgerKeyClaimableBalanceW;

        // LazyLedgerKeyLiquidityPool (opaque only)
        #[cxx_name = "LazyLedgerKeyLiquidityPool"]
        type LazyLedgerKeyLiquidityPoolW;

        // LazyLedgerKeyContractData (opaque only)
        #[cxx_name = "LazyLedgerKeyContractData"]
        type LazyLedgerKeyContractDataW;

        // LazyLedgerKeyContractCode (opaque only)
        #[cxx_name = "LazyLedgerKeyContractCode"]
        type LazyLedgerKeyContractCodeW;

        // LazyLedgerKeyConfigSetting (opaque only)
        #[cxx_name = "LazyLedgerKeyConfigSetting"]
        type LazyLedgerKeyConfigSettingW;

        // LazyLedgerKeyTtl (opaque only)
        #[cxx_name = "LazyLedgerKeyTtl"]
        type LazyLedgerKeyTtlW;

        // LazyInvokeContractArgs (opaque only)
        #[cxx_name = "LazyInvokeContractArgs"]
        type LazyInvokeContractArgsW;

        // LazyCreateContractArgs (opaque only)
        #[cxx_name = "LazyCreateContractArgs"]
        type LazyCreateContractArgsW;

        // LazyBytesM (opaque only)
        #[cxx_name = "LazyBytesM"]
        type LazyBytesMW;

        // LazyCreateContractArgsV2 (opaque only)
        #[cxx_name = "LazyCreateContractArgsV2"]
        type LazyCreateContractArgsV2W;

        // LazySorobanCredentials (opaque only)
        #[cxx_name = "LazySorobanCredentials"]
        type LazySorobanCredentialsW;

        // LazySorobanAuthorizedInvocation (opaque only)
        #[cxx_name = "LazySorobanAuthorizedInvocation"]
        type LazySorobanAuthorizedInvocationW;
    }
}