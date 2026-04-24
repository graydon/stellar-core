use crate::{
    lazy_xdr_bridge::{
        LazyHostFunctionW, LazyLedgerEntryVecW, LazySorobanAuthorizationEntryVecW,
        LazySorobanResourcesW, LazyTtlEntryVecW,
    },
    soroban_proto_all::get_host_module_for_protocol, CxxBuf, CxxFeeConfiguration,
    CxxLedgerEntryRentChange, CxxLedgerInfo, CxxLedgerInfoLazy, CxxRentFeeConfiguration,
    CxxRentFeeConfigurationLazy, CxxRentWriteFeeConfiguration, CxxTransactionResources, FeePair,
    InvokeHostFunctionOutput, SorobanModuleCache,
};

pub(crate) fn invoke_host_function(
    config_max_protocol: u32,
    enable_diagnostics: bool,
    instruction_limit: u32,
    hf_buf: &CxxBuf,
    resources_buf: CxxBuf,
    restored_rw_entry_indices: &Vec<u32>,
    source_account_buf: &CxxBuf,
    auth_entries: &Vec<CxxBuf>,
    ledger_info: CxxLedgerInfo,
    ledger_entries: &Vec<CxxBuf>,
    ttl_entries: &Vec<CxxBuf>,
    base_prng_seed: &CxxBuf,
    rent_fee_configuration: CxxRentFeeConfiguration,
    module_cache: &SorobanModuleCache,
) -> Result<InvokeHostFunctionOutput, Box<dyn std::error::Error>> {
    let hm = get_host_module_for_protocol(config_max_protocol, ledger_info.protocol_version)?;
    let res = (hm.invoke_host_function)(
        enable_diagnostics,
        instruction_limit,
        hf_buf,
        &resources_buf,
        restored_rw_entry_indices,
        source_account_buf,
        auth_entries,
        &ledger_info,
        ledger_entries,
        ttl_entries,
        base_prng_seed,
        &rent_fee_configuration,
        module_cache,
    );

    #[cfg(feature = "testutils")]
    crate::soroban_test_extra_protocol::maybe_invoke_host_function_again_and_compare_outputs(
        &res,
        &hm,
        config_max_protocol,
        enable_diagnostics,
        instruction_limit,
        hf_buf,
        resources_buf,
        restored_rw_entry_indices,
        source_account_buf,
        auth_entries,
        ledger_info,
        ledger_entries,
        ttl_entries,
        base_prng_seed,
        rent_fee_configuration,
        module_cache,
    );

    res
}

/// Lazy invocation path: passes lazy XDR handles directly through
/// to the host via the HostModule dispatch table, avoiding byte
/// materialization.
pub(crate) fn invoke_host_function_lazy(
    config_max_protocol: u32,
    enable_diagnostics: bool,
    instruction_limit: u32,
    hf: &LazyHostFunctionW,
    resources: &LazySorobanResourcesW,
    restored_rw_entry_indices: &Vec<u32>,
    source_account: &[u8],
    auth_entries: &LazySorobanAuthorizationEntryVecW,
    ledger_info: CxxLedgerInfoLazy,
    ledger_entries: &LazyLedgerEntryVecW,
    ttl_entries: &LazyTtlEntryVecW,
    base_prng_seed: &[u8],
    rent_fee_configuration: CxxRentFeeConfigurationLazy,
    module_cache: &SorobanModuleCache,
) -> Result<InvokeHostFunctionOutput, Box<dyn std::error::Error>> {
    use std::error::Error as StdError;
    type BoxStdErr = Box<dyn StdError>;
    type BoxStdErrSend = Box<dyn StdError + Send>;
    type BoxStdErrSendSync = Box<dyn StdError + Send + Sync>;

    fn sendable_str_err(str: &str) -> BoxStdErrSend {
        let tmp: BoxStdErrSendSync = Box::from(str);
        tmp as BoxStdErrSend
    }

    let hm = get_host_module_for_protocol(config_max_protocol, ledger_info.protocol_version)?;

    let large_stack_size: usize = 100 * 1024 * 1024;
    let res = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(large_stack_size)
            .spawn_scoped(scope, || {
                (hm.invoke_host_function_lazy)(
                    enable_diagnostics,
                    instruction_limit,
                    &hf.0,
                    &resources.0,
                    restored_rw_entry_indices.as_slice(),
                    source_account,
                    &auth_entries.0,
                    &ledger_info,
                    &ledger_entries.0,
                    &ttl_entries.0,
                    base_prng_seed,
                    &rent_fee_configuration,
                    module_cache,
                )
                .map_err(|e| sendable_str_err(&format!("{e}")))
            })
            .map_err(|_| sendable_str_err("spawn_scoped failed"))?
            .join()
            .map_err(|_| sendable_str_err("join failed"))?
    });

    res.map_err(|e: BoxStdErrSend| e as BoxStdErr)
}

pub(crate) fn compute_transaction_resource_fee(
    config_max_protocol: u32,
    protocol_version: u32,
    tx_resources: CxxTransactionResources,
    fee_config: CxxFeeConfiguration,
) -> Result<FeePair, Box<dyn std::error::Error>> {
    let hm = get_host_module_for_protocol(config_max_protocol, protocol_version)?;
    Ok((hm.compute_transaction_resource_fee)(
        tx_resources,
        fee_config,
    ))
}

pub(crate) fn can_parse_transaction(
    config_max_protocol: u32,
    protocol_version: u32,
    xdr: &CxxBuf,
    depth_limit: u32,
) -> Result<bool, Box<dyn std::error::Error>> {
    let hm = get_host_module_for_protocol(config_max_protocol, protocol_version)?;
    Ok((hm.can_parse_transaction)(xdr, depth_limit))
}

pub(crate) fn compute_rent_fee(
    config_max_protocol: u32,
    protocol_version: u32,
    changed_entries: &Vec<CxxLedgerEntryRentChange>,
    fee_config: CxxRentFeeConfiguration,
    current_ledger_seq: u32,
) -> Result<i64, Box<dyn std::error::Error>> {
    let hm = get_host_module_for_protocol(config_max_protocol, protocol_version)?;
    Ok((hm.compute_rent_fee)(
        changed_entries,
        fee_config,
        current_ledger_seq,
    ))
}

pub(crate) fn compute_rent_write_fee_per_1kb(
    config_max_protocol: u32,
    protocol_version: u32,
    bucket_list_size: i64,
    fee_config: CxxRentWriteFeeConfiguration,
) -> Result<i64, Box<dyn std::error::Error>> {
    let hm = get_host_module_for_protocol(config_max_protocol, protocol_version)?;
    Ok((hm.compute_rent_write_fee_per_1kb)(
        bucket_list_size,
        fee_config,
    ))
}
