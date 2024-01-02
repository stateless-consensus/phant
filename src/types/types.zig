// Raw types.
pub const Hash32 = [32]u8;
pub const Bytes32 = [32]u8;
pub const Bytes31 = [31]u8;

// Ethereum execution layer types.
pub const Bytecode = []const u8;
pub const Address = [20]u8;

// State.
pub const AccountState = @import("account_state.zig");

// Blocks
pub const block = @import("block.zig");
pub const empty_uncle_hash = block.empty_uncle_hash;
pub const Block = block.Block;
pub const BlockHeader = block.BlockHeader;
pub const LogsBloom = block.LogsBloom;
pub const Withdrawal = @import("withdrawal.zig");

// Transactions
const transaction = @import("transaction.zig");
pub const AccessListTuple = transaction.AccessListTuple;
pub const Txn = transaction.Txn;
pub const TxnTypes = transaction.TxnTypes;
pub const LegacyTxn = transaction.LegacyTxn;
pub const AccessListTxn = transaction.AccessListTxn;
pub const MarketFeeTxn = transaction.MarketFeeTxn;
