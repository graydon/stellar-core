@external("env", "log_value")
export declare function log_value(v: u64): u64;

@external("env", "get_current_ledger_num")
export declare function get_current_ledger_num(): u64;

@external("env", "get_current_ledger_close_time")
export declare function get_current_ledger_close_time(): u64;
