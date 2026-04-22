# Lazy XDR Rewrite Plan

## Original Request from user (as written)

I want you to start working on a fairly involved rewrite of the way we work with XDR data types in this repository specifically those flowing to and from soroban, and access routines inside the soroban host.

This is an experiment. It's not that important that you have everything working. I just wanna get the basic and functionality wired up to see how well it works even theoretically.

The main change is I want to start using a new representation of XDR that I (well, you) just built in a branch of the XDR generation library. this is "lazy XDR" and it's in the LazyXdr4 branch of rs-stellar-xdr, specifically in this repo https://github.com/graydon/rs-stellar-xdr/tree/LazyXdr4 -- it should be used instead of the one which is referenced by the soroban host library as a dependency.

I don't need you to use this library everywhere in stellar-core. that's too much. and lots of places would be inappropriate. But I'd like you to make a plan for using it in the transaction apply path for soroban transactions, for the data passed into them and coming back out of them, and used within them. So this will be anything that's a ledger entry in the footprint or modified output LEs of the tx, or SCVals as arguments or returns from the tx.

I also want you to use these lazy rust handles-to-XDR-blobs instead of unpacked ledger entries and scvals _on the C++ side_, using the cxx C++-to-rust bridge code, calling methods on the rust objects as needed but _not_ serializing/deserializing the whole XDR structures for each transaction. You should just be forming rust lazy XDR handles at the beginning of the transaction-execution phase, and then passing vectors of such handles back and forth between maps in the C++ parallel execution framework and the soroban host.

most invasively: I want you to modify the soroban host itself to no longer deserialize XDR at all, nor convert it into the "Host Object" format. the Val interface to guests can stay the same, but the internal representation of SCVals should just be lazy handles to XDR buffers with serialized SCVals. Likewise the storage maps: not deserialized / materialized LedgerEntry structures; just lazy handles to XDR buffers with still-serialized LedgerEntries in them.

you'll need to modify the soroban host (the most recent one, p26) to achieve this. and you'll need to modify the build system to install, build and run the xdr generator in the mode that generates a cxx bridge module, and extend the existing cxx bridge module generation to incorporate an additional bridge module (the one emitted by the XDR generator -- we taught it to emit bridge modules).

I know this is a lot! You're going to have to make a written plan for it and probably study a lot first. you're also going to need to run lots of subagents to divide up the work, and track your progress. start by writing my entire request here to a file and then extend it with your plan of action and then check in with me for confirmation or discussion before you start, and as you work.

---

## Research Summary

### Current Architecture (how data flows today)

**C++ → Rust (entry):**
1. `InvokeHostFunctionOpFrame` gathers `LedgerEntry` objects from C++ LedgerTxn
2. Each is serialized to XDR bytes via `toCxxBuf()` → `CxxBuf{UniquePtr<CxxVector<u8>>}`
3. Vectors of CxxBuf passed across cxx bridge to `invoke_host_function()`
4. Rust side deserializes each CxxBuf → full `LedgerEntry`, `HostFunction`, `ScVal`, etc.
5. Host creates `Storage` with `MeteredOrdMap<Rc<LedgerKey>, Option<(LedgerEntry, ttl)>>`

**Inside the host:**
- SCVals become `Val` (64-bit tagged value) via `to_host_val()`
- Complex values (Vec, Map, Bytes, String, etc.) become `HostObject` entries in a flat Vec
- Every field access is through the materialized Rust enum structure
- Storage reads deserialize LedgerEntry → extract ScVal → materialize to HostObject graph

**Rust → C++ (exit):**
- Modified entries serialized back to XDR bytes → `RustBuf{Vec<u8>}`
- C++ deserializes results via `xdr::xdr_from_opaque()`

### LazyXdr4 Branch (https://github.com/graydon/rs-stellar-xdr/tree/LazyXdr4)

Provides:
- `LazyHandle`: `Arc<[u8]>` + offset + length — shared ownership of validated XDR region
- `LazyXdr` trait: `xdr_validate()`, `xdr_len()`, `from_xdr_at()` — zero-copy access
- Generated lazy wrappers for every XDR type (e.g. `LazyScVal`, `LazyLedgerEntry`,
  `LazyLedgerKey`, `LazyScAddress`, etc.)
- Built-in lazy wrappers: `LazyBytesM`, `LazyStringM`, `LazyVecM`, `LazyFixedArray`,
  `LazyOpaqueFixed`, `LazyOption`
- CXX bridge template: generates `#[cxx::bridge] mod ffi` with `Box<LazyFoo>` types
  and `cxx_from_bytes()` / `cxx_field_name()` accessor methods
- Eager↔Lazy conversion via `TryFrom<&ScVal> for LazyScVal` and vice versa

### Key Types for This Work

- `LazyLedgerEntry` — struct with `.last_modified_ledger_seq()`, `.data()`, `.ext()`
- `LazyLedgerEntryData` — union: `.as_account()`, `.as_contract_data()`, etc.
- `LazyLedgerKey` — union
- `LazyScVal` — union with `.discriminant_i32()`, `.as_u32()`, `.as_map()`, etc.
- `LazyScMap` = `LazyVecM<LazyScMapEntry>` with `.get(i)`, `.iter()`
- CXX bridge provides `cxx_from_bytes(&[u8]) -> Result<Box<LazyT>>`

---

## Detailed Plan of Action (v2 — revised per user feedback)

### Design Principles (from user feedback)

1. **No HostObject at all in p26 soroban**: Get rid of the HostObject enum
   entirely. All SCVals are just lazy handles. Mutations use copy-on-write:
   copy bytes out → transient eager version → modify → serialize back.
   Remove all interconversion logic.

2. **Lazy handles across the ENTIRE parallel execution phase on C++ side**:
   Not just inside one InvokeHostFunctionOpFrame. The three-tier parallel state
   hierarchy (`GlobalParallelApplyLedgerState` → `ThreadParallelApplyLedgerState`
   → `TxParallelApplyLedgerState`) should hold lazy handles as the primary
   representation. Entries reused from one tx to the next stay as lazy handles.
   The benefit comes from reusing the same LEs across transactions without
   re-serializing/deserializing.

3. **Protocol branching on C++ side**: The `soroban_proto_all` dispatcher
   assumes similar input signatures for all protocols. Instead, branch on
   C++ side: "are we running old protocols?" If old protocol, copy data OUT
   of the rust lazy handle to materialize a CxxBuf for the old-protocol Rust
   interface. It's fine to make temporary buffer copies for old protocols
   (back-compat only). The primary C++ representation in the parallel phase
   should be "whatever the newest protocol needs" = lazy rust-buffer handles.

4. **LedgerKeys also lazy in soroban storage maps**: Use `LazyLedgerKey`
   alongside `LazyLedgerEntry` in the Storage type.

5. **Tests can break**: Some way to meter is needed, but approximate is fine.
   E.g. charge byte-read for the max size of 2 XDRs being compared before
   calling the Ord implementation on lazy handles.

6. **Performance comparison target**: Get at least SAC (builtin contract, no
   WASM) end-to-end test running. Ideally also a WASM example.

---

### Phase 1: Dependency Wiring

**Goal**: Wire up the LazyXdr4 stellar-xdr crate as the XDR dependency for
p26 soroban and for the main stellar-core Rust crate.

**Steps:**
1. In `src/rust/soroban/p26/Cargo.toml`:
   - Change `stellar-xdr` dependency to point to LazyXdr4 branch:
     ```toml
     [workspace.dependencies.stellar-xdr]
     git = "https://github.com/graydon/rs-stellar-xdr"
     branch = "LazyXdr4"
     features = ["curr", "alloc"]
     ```
2. In `src/rust/Cargo.toml`:
   - Add direct dependency on stellar-xdr from LazyXdr4 for the bridge types
3. Update `Cargo.lock` files accordingly
4. Disable dep-tree checks temporarily (expected trees will be wrong)

**Files to modify:**
- `src/rust/soroban/p26/Cargo.toml`
- `src/rust/Cargo.toml`
- `src/rust/soroban/p26/Cargo.lock`

### Phase 2: Build System — CXX Bridge for Lazy Types

**Goal**: Generate a second cxx bridge module from the LazyXdr4-generated types
so that C++ can hold and manipulate `Box<LazyLedgerEntry>`, `Box<LazyLedgerKey>`,
`Box<LazyScVal>`, etc.

**Steps:**
1. Add bridge functions + impl blocks in a new Rust source file (e.g.
   `src/rust/src/lazy_xdr_bridge.rs`) that wraps the generated lazy types
   with cxx-compatible accessors:
   - `lazy_ledger_entry_from_bytes(&[u8]) -> Result<Box<LazyLedgerEntry>>`
   - `lazy_ledger_key_from_bytes(&[u8]) -> Result<Box<LazyLedgerKey>>`
   - `lazy_scval_from_bytes(&[u8]) -> Result<Box<LazyScVal>>`
   - `lazy_xdr_bytes(handle) -> &[u8]` (extract backing bytes for old-protocol compat)
   - Field accessors as needed
2. Run `cxxbridge` on the new bridge module → `LazyXdrBridge.h/cpp`
3. Add Makefile.am rules for the new bridge module generation
4. Include both bridge headers in relevant C++ files

**Files to modify:**
- `src/rust/src/lazy_xdr_bridge.rs` (new)
- `src/rust/src/lib.rs` — include module
- `src/Makefile.am` — new cxxbridge rules
- Generated: `rust/LazyXdrBridge.h`, `rust/LazyXdrBridge.cpp`

### Phase 3: Rust Bridge Layer — Lazy Invocation Path

**Goal**: Add a new `invoke_host_function_lazy()` entry point that accepts
and returns lazy XDR handles directly — no CxxBuf intermediary. The C++ side
holds `rust::Box<LazyLedgerEntry>` etc. throughout the parallel phase and
passes vectors of those opaque handle boxes straight into this function.

**Steps:**
1. New bridge function in `bridge.rs`:
   ```rust
   fn invoke_host_function_lazy(
       config_max_protocol: u32,
       enable_diagnostics: bool,
       instruction_limit: u32,
       hf: &Box<LazyHostFunction>,                    // contains LazyScVal args
       resources_buf: CxxBuf,                          // SorobanResources — small, ok eager
       source_account_buf: &CxxBuf,
       auth_entries: &Vec<Box<LazySorobanAuthorizationEntry>>,  // opaque handles
       ledger_info: CxxLedgerInfo,
       ledger_entries: &Vec<Box<LazyLedgerEntry>>,     // opaque handles from C++
       ttl_entries: &Vec<Box<LazyLedgerEntry>>,        // opaque handles from C++
       base_prng_seed: &CxxBuf,
       rent_fee_configuration: CxxRentFeeConfiguration,
       module_cache: &SorobanModuleCache,
   ) -> Result<InvokeHostFunctionOutputLazy>
   ```
   `LazyHostFunction` is important because it contains the `LazyScVal` args
   passed as contract invocation arguments — these may be large and are
   reused across re-invocations. Auth entries similarly contain ScVals and
   are reused/shared between transactions.
2. New output type `InvokeHostFunctionOutputLazy`:
   ```rust
   struct InvokeHostFunctionOutputLazy {
       success: bool,
       is_internal_error: bool,
       diagnostic_events: Vec<RustBuf>,                // small, ok as bytes
       cpu_insns: u64,
       mem_bytes: u64,
       time_nsecs: u64,
       result_value: Box<LazyScVal>,                   // opaque handle
       modified_ledger_entries: Vec<Box<LazyLedgerEntry>>,  // opaque handles
       contract_events: Vec<RustBuf>,                  // small, ok as bytes
       rent_fee: i64,
   }
   ```
   Handles come back as `Box<LazyFoo>` — C++ holds them directly, no
   deserialization needed. C++ can re-form `rust::Vec<rust::Box<LazyLedgerEntry>>`
   to pass into the next transaction or store in the parallel state maps.
3. In `soroban_proto_any.rs` (p26 only): new function that takes the lazy
   handles directly, passes them into the modified host, and returns lazy
   handles for output.
4. **Protocol dispatch on C++ side**, not in `soroban_proto_all.rs`:
   - C++ checks protocol version
   - If p26+: calls `invoke_host_function_lazy()` passing the lazy handles
     it already holds
   - If older: extracts backing bytes from lazy handles via
     `lazy_xdr_bytes()` → forms CxxBuf → calls old `invoke_host_function()`

**Files to modify:**
- `src/rust/src/bridge.rs`
- `src/rust/src/soroban_invoke.rs`
- `src/rust/src/soroban_proto_any.rs` (p26 version)
- `src/rust/src/soroban_proto_all.rs` (new p26-specific entry)

### Phase 4: Soroban Host (p26) — Eliminate HostObject, Use Lazy Everywhere

**Goal**: Gut the HostObject system in p26 soroban host. Replace with lazy
XDR handles throughout.

**Sub-phase 4a: Lazy Storage**
1. Change `StorageMap` type:
   - From: `MeteredOrdMap<Rc<LedgerKey>, Option<(LedgerEntry, live_until)>>`
   - To: `MeteredOrdMap<LazyLedgerKey, Option<(LazyLedgerEntry, live_until)>>`
   - Keys: `LazyLedgerKey` (implements `Ord`, `Eq`, `Hash`)
   - Values: `LazyLedgerEntry` handles
2. Change `FootprintMap`:
   - From: `MeteredOrdMap<Rc<LedgerKey>, AccessType>`
   - To: `MeteredOrdMap<LazyLedgerKey, AccessType>`
3. Modify `e2e_invoke.rs`:
   - Accept lazy handles as input
   - Build footprint/snapshot from lazy handles (no deserialization)
   - Return lazy handles for output (unmodified entries return original bytes)

**Sub-phase 4b: Eliminate HostObject**
1. Remove `HostObject` enum entirely (or reduce to a single `Lazy(LazyScVal)` variant)
2. The host's `objects: Vec<HostObject>` becomes `objects: Vec<LazyScVal>`
3. `to_host_val(scval)`:
   - Scalars (u32, i32, bool, etc.) still encode directly into Val's 64 bits
   - Complex types: serialize ScVal to XDR bytes → wrap as `LazyScVal` →
     store in objects vec → return Object handle Val
   - But most paths won't even have an `ScVal` — they'll already have a
     `LazyScVal` from storage, so just store it directly
4. `from_host_val(val)`:
   - Scalars: extract directly from Val bits
   - Objects: get `LazyScVal` from objects vec → return its backing bytes
     (zero-copy for unmodified objects)
5. Mutation (copy-on-write):
   - When a guest modifies a value (e.g. map_put, vec_push):
     a. Deserialize the `LazyScVal` → eager `ScVal` (one-time cost)
     b. Modify the eager `ScVal`
     c. Serialize back → new `LazyScVal`
     d. Store the new lazy handle in the objects vec
   - This means mutations are no cheaper than today, but reads are zero-copy
6. Host functions that access fields of lazy objects:
   - `map_get(lazy_map, key)`: use `LazyScMap` iterator + `LazyScVal::cmp()`
   - `vec_get(lazy_vec, idx)`: use `LazyScVec::get(idx)`
   - `symbol_to_str(lazy_sym)`: use `LazyScSymbol::as_bytes()`
   - etc.
7. Remove all the `ScVal ↔ HostObject` interconversion code

**Sub-phase 4c: Metering**
1. Approximate metering for lazy operations:
   - Before any `LazyScVal::cmp()`: charge `ValDeser` for `max(lhs.len(), rhs.len())`
   - Before any lazy field access: charge `ValDeser` for field size
   - Before COW mutation: charge `ValDeser` + `ValSer` for full object size
2. This will over-count (we charge as if deserializing even though we don't)
   but preserves the budget accounting invariant.

**Files to modify:**
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs`
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs`
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs`
- `src/rust/soroban/p26/soroban-env-host/src/host.rs`
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs`
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`

### Phase 5: C++ Parallel Execution Framework — Lazy Throughout

**Goal**: Make `rust::Box<LazyLedgerEntry>` (opaque Rust handle types) the
primary representation in the entire parallel execution framework. C++ never
unpacks these into C++ XDR structs during the parallel phase — it just holds
the opaque boxes and passes them around.

**Steps:**
1. **Entry maps**: Change the entry type in the parallel state hierarchy:
   - `ParallelApplyEntryMap` currently holds `LedgerEntry` (C++ XDR struct)
   - Change to hold `rust::Box<LazyLedgerEntry>` (or a thin C++ wrapper)
   - The wrapper owns the `rust::Box` and provides move semantics
   - Similarly for LedgerKey: hold `rust::Box<LazyLedgerKey>`
2. **Entry loading**: When entries first enter the parallel phase (from
   `ApplyLedgerView` or `InMemorySorobanState`):
   - Serialize to XDR bytes (as today when loading from bucket list)
   - Call `lazy_ledger_entry_from_bytes(bytes)` → get `rust::Box<LazyLedgerEntry>`
   - This is the **only** point where lazy handles are formed
   - From here on, the handle is reused across transactions in the same
     cluster/stage — no re-serializing or re-wrapping
3. **Entry writing**: When committing changes back to `AbstractLedgerTxn`
   (at the end of the parallel phase):
   - Call `lazy_xdr_bytes(handle)` to extract the backing `&[u8]`
   - Deserialize to C++ XDR struct for the LedgerTxn write (only at final commit)
   - This is the **only** point where C++ XDR structs are formed from lazy data
4. **InvokeHostFunctionOpFrame** changes:
   - `invokeHostFunction()` receives lazy handles from the entry maps
   - Assembles `rust::Vec<rust::Box<LazyLedgerEntry>>` from the map entries
   - Protocol check: if p26+, pass vector of handles directly to
     `invoke_host_function_lazy()` — handles go straight through to host
   - If older: for each handle, call `lazy_xdr_bytes()` → form `CxxBuf` →
     call old `invoke_host_function()` (temporary copy, back-compat only)
   - Output (p26+): receives `Vec<Box<LazyLedgerEntry>>` back — stores
     handles directly into the entry maps for the next transaction
5. **TTL entries**: Same treatment — `rust::Box<LazyLedgerEntry>` for TTL entries
   (TTL entries are just LedgerEntry with TtlEntry data, same lazy type)

**Files to modify:**
- `src/transactions/ParallelApplyUtils.h` — entry map types
- `src/transactions/ParallelApplyUtils.cpp` — loading, merging, committing
- `src/transactions/InvokeHostFunctionOpFrame.cpp` — protocol branching
- `src/transactions/InvokeHostFunctionOpFrame.h`
- `src/ledger/LedgerManagerImpl.cpp` — final commit path
- Possibly `src/ledger/InMemorySorobanState.h/cpp`

### Phase 6: End-to-End Test — SAC Performance Comparison

**Goal**: Get at least one SAC (Stellar Asset Contract — builtin, no WASM)
test running end-to-end with the lazy XDR path, and compare performance.

**Steps:**
1. Identify existing SAC test(s) in the test suite
2. Ensure the lazy path executes correctly for SAC operations:
   - SAC transfer, balance, mint, etc.
   - These use builtin contract dispatch, no WASM VM
3. Add a simple benchmark or timing harness:
   - Run N SAC operations via old path (eager)
   - Run N SAC operations via new path (lazy)
   - Compare wall-clock time and budget consumption
4. (Stretch) Get a simple WASM contract test running too
5. It's OK if many tests break — focus on getting the SAC path clean

**Files to modify:**
- Existing test files for SAC operations
- Possibly new benchmark file

---

## Execution Order

```
Phase 1 (Dep Wiring)
  → Phase 2 (Build System / Bridge)
     → Phase 3 (Rust Bridge Layer)
        → Phase 4 (Host Gutting — parallel with Phase 5)
        → Phase 5 (C++ Parallel Framework — parallel with Phase 4)
           → Phase 6 (End-to-End Test)
```

**Recommended order**: 1 → 2 → 3 → 4+5 (interleaved) → 6

Start with dependency wiring and build system since everything else depends
on having the lazy types available. Then the Rust bridge layer. Then the two
big pieces (host modifications + C++ framework) can be done somewhat in
parallel since they're on opposite sides of the bridge. Finally wire up an
end-to-end test.

---

## Risk Assessment & Notes

- **This is experimental**: The goal is proof-of-concept. Tests may break.
  Focus on getting the core data path working.
- **Metering**: Over-counting is fine. Charge byte-read for max XDR size
  before comparisons. Charge ValDeser/ValSer for COW mutations.
- **Old protocols**: C++ side branches on protocol. Old protocols get
  temporary buffer copies from lazy handles back into CxxBufs. This is
  slightly wasteful but only affects back-compat paths.
- **Mutation cost**: Copy-on-write means mutations are no cheaper than
  today. The win is on the read path, which dominates most transactions
  (most footprint entries are read-only).
- **Memory**: `LazyHandle` uses `Arc<[u8]>` — reference-counted shared
  ownership. Multiple handles can share the same backing buffer.
  Sub-handles (field accessors) share the parent's Arc.
- **Thread safety**: `Arc<[u8]>` is `Send + Sync`. Lazy handles can be
  shared across threads in the parallel framework.
- **Performance target**: SAC operations are a good first target because
  they don't involve WASM VM instantiation overhead, isolating the
  XDR handling cost.
