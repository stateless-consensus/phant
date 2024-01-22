const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const state = @import("state.zig");
const Allocator = std.mem.Allocator;
const Address = types.Address;
const AddressSet = common.AddressSet;
const AddressKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const AccountData = state.AccountData;
const AccountState = state.AccountState;
const Bytes32 = types.Bytes32;
const log = std.log.scoped(.statedb);

pub const StateDB = struct {
    const AccountDB = std.AutoHashMap(Address, AccountState);

    allocator: Allocator,
    db: AccountDB,

    // Tx scoped variables.
    original_db: ?AccountDB = null,
    accessed_accounts: AddressSet,
    accessed_storage_keys: AddressKeySet,

    pub fn init(allocator: Allocator, accounts: []AccountState) !StateDB {
        var db = AccountDB.init(allocator);
        try db.ensureTotalCapacity(@intCast(accounts.len));
        for (accounts) |account| {
            db.putAssumeCapacityNoClobber(account.addr, account);
        }
        return .{
            .allocator = allocator,
            .db = db,
            .accessed_accounts = AddressSet.init(allocator),
            .accessed_storage_keys = AddressKeySet.init(allocator),
        };
    }

    pub fn deinit(self: *StateDB) void {
        self.db.deinit();
        self.accessed_accounts.deinit();
        self.accessed_storage_keys.deinit();
        if (self.original_db) |*original_db| {
            original_db.deinit();
        }
    }

    pub fn startTx(self: *StateDB) !void {
        if (self.original_db) |*original_db| {
            original_db.deinit();
        }
        self.original_db = try self.db.clone();
        self.accessed_accounts.clearRetainingCapacity();
        self.accessed_storage_keys.clearRetainingCapacity();
    }

    pub fn getAccountOpt(self: *StateDB, addr: Address) ?AccountData {
        const account_data = self.db.get(addr) orelse return null;
        return .{
            .nonce = account_data.nonce,
            .balance = account_data.balance,
            .code = account_data.code,
        };
    }

    pub fn getAccount(self: *StateDB, addr: Address) AccountData {
        return self.getAccountOpt(addr) orelse AccountData{
            .nonce = 0,
            .balance = 0,
            .code = &[_]u8{},
        };
    }

    pub fn getStorage(self: *StateDB, addr: Address, key: u256) Bytes32 {
        const account = self.db.get(addr) orelse return std.mem.zeroes(Bytes32);
        return account.storage.get(key) orelse std.mem.zeroes(Bytes32);
    }

    pub fn getOriginalStorage(self: *StateDB, addr: Address, key: u256) Bytes32 {
        const account = self.original_db.?.get(addr) orelse return std.mem.zeroes(Bytes32);
        return account.storage.get(key) orelse std.mem.zeroes(Bytes32);
    }

    pub fn getAllStorage(self: *StateDB, addr: Address) ?std.AutoHashMap(u256, Bytes32) {
        const account = self.db.get(addr) orelse return null;
        return account.storage;
    }

    pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: Bytes32) !void {
        var account = self.db.getPtr(addr) orelse return error.AccountDoesNotExist;
        try account.storage.put(key, value);
    }

    pub fn setBalance(self: *StateDB, addr: Address, balance: u256) !void {
        var account = self.db.getPtr(addr);
        if (account) |acc| {
            acc.balance = balance;
            return;
        }
        try self.db.put(addr, try AccountState.init(self.allocator, addr, 0, balance, &[_]u8{}));
    }

    pub fn incrementNonce(self: *StateDB, addr: Address) !void {
        var account = self.db.getPtr(addr) orelse return error.AccountDoesNotExist;
        account.nonce += 1;
    }

    pub fn destroyAccount(self: *StateDB, addr: Address) void {
        _ = self.db.remove(addr);
    }

    pub fn accountExistsAndIsEmpty(self: *StateDB, addr: Address) bool {
        const account = self.db.get(addr) orelse return false;
        return account.nonce == 0 and account.balance == 0 and account.code.len == 0;
    }

    pub fn accessedAccountsContains(self: *StateDB, addr: Address) bool {
        return self.accessed_accounts.contains(addr);
    }

    pub fn putAccessedAccount(self: *StateDB, addr: Address) !void {
        try self.accessed_accounts.putNoClobber(addr, {});
    }

    pub fn accessedStorageKeysContains(self: *StateDB, addrkey: AddressKey) bool {
        return self.accessed_storage_keys.contains(addrkey);
    }

    pub fn putAccessedStorageKeys(self: *StateDB, addrkey: AddressKey) !void {
        try self.accessed_storage_keys.putNoClobber(addrkey, {});
    }

    pub fn snapshot(self: StateDB) !StateDB {
        // TODO: while simple this is quite inefficient.
        // A much smarter way is doing some "diff" style snapshotting or similar.
        return StateDB{
            .allocator = self.allocator,
            .db = try self.db.clone(),
            .original_db = try self.original_db.?.clone(),
            .accessed_accounts = try self.accessed_accounts.clone(),
            .accessed_storage_keys = try self.accessed_storage_keys.clone(),
        };
    }
};
