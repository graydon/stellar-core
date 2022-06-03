// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

use crate::{log::partition::TX, rust_bridge::XDRBuf};
use log::info;
use std::io::Cursor;

use cxx::CxxString;
use im_rc::OrdMap;
use std::error::Error;
use stellar_contract_env_host::{
    storage, xdr,
    xdr::{
        ContractDataEntry, LedgerEntry, LedgerEntryData, ReadXdr, ScObject, ScStatic, ScVal, ScVec,
        WriteXdr,
    },
    Host, HostError, Vm,
};

/// Deserialize an SCVec XDR object of SCVal arguments from the C++ side of the
/// bridge, instantiate a Host and VM with the provided WASM, invoke the
/// requested function in the WASM, and serialize an SCVal back into a return
/// value.
pub(crate) fn invoke_contract(
    contract_id: &XDRBuf,
    func: &CxxString,
    args: &XDRBuf,
    footprint: &XDRBuf,
    ledger_entries: &Vec<XDRBuf>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let contract_id = xdr::Hash::read_xdr(&mut Cursor::new(contract_id.data.as_slice()))?;
    let arg_scvals = ScVec::read_xdr(&mut Cursor::new(args.data.as_slice()))?;
    let xdr::Footprint {
        read_only,
        read_write,
    } = xdr::Footprint::read_xdr(&mut Cursor::new(footprint.data.as_slice()))?;
    let mut map = OrdMap::new();
    let mut access = OrdMap::new();
    for lk in read_only.to_vec() {
        match lk {
            xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData { contract_id, key }) => {
                let sk = storage::Key { contract_id, key };
                access.insert(sk, storage::AccessType::ReadOnly);
            }
            _ => return Err(HostError::General("unexpected ledger key type").into()),
        }
    }
    for lk in read_write.to_vec() {
        match lk {
            xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData { contract_id, key }) => {
                let sk = storage::Key { contract_id, key };
                access.insert(sk, storage::AccessType::ReadWrite);
            }
            _ => return Err(HostError::General("unexpected ledger key type").into()),
        }
    }
    for buf in ledger_entries {
        let le = LedgerEntry::read_xdr(&mut Cursor::new(buf.data.as_slice()))?;
        match le.data {
            LedgerEntryData::ContractData(ContractDataEntry {
                key,
                val,
                contract_id,
            }) => {
                let sk = storage::Key { contract_id, key };
                if !access.contains_key(&sk) {
                    return Err(HostError::General("ledger entry not found in footprint").into());
                }
                map.insert(sk.clone(), Some(val));
            }
            _ => return Err(HostError::General("unexpected ledger entry type").into()),
        }
    }
    for k in access.keys() {
        if !map.contains_key(k) {
            return Err(HostError::General("ledger entry not found for footprint entry").into());
        }
    }
    let wasm_key = storage::Key {
        contract_id: contract_id.clone(),
        key: ScVal::Static(ScStatic::LedgerKeyContractCodeWasm),
    };
    let wasm = match map.get(&wasm_key) {
        Some(Some(ScVal::Object(Some(ScObject::Binary(blob))))) => blob.clone(),
        Some(_) => {
            return Err(HostError::General(
                "unexpected value type for LEDGER_KEY_CONTRACT_CODE_WASM",
            )
            .into())
        }
        None => {
            return Err(
                HostError::General("missing value for LEDGER_KEY_CONTRACT_CODE_WASM").into(),
            )
        }
    };

    let func_str = func.to_str()?;

    let footprint = storage::Footprint(access);
    let storage = storage::Storage::with_enforcing_footprint_and_map(footprint, map);
    let mut host = Host::with_storage(storage);
    let vm = Vm::new(&host, contract_id, wasm.as_slice())?;

    info!(target: TX, "Invoking contract function '{}'", func);
    let res = vm.invoke_function(&mut host, func_str, &arg_scvals)?;

    let mut ret_xdr_buf: Vec<u8> = Vec::new();
    res.write_xdr(&mut Cursor::new(&mut ret_xdr_buf))?;
    Ok(ret_xdr_buf)
}
