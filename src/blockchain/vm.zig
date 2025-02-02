const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const params = @import("params.zig");
const blockchain_types = @import("types.zig");
const EVM = @import("zevem").EVM;
const Allocator = std.mem.Allocator;
const AddressSet = common.AddressSet;
const AddressKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const Environment = blockchain_types.Environment;
const Message = blockchain_types.Message;
const Block = types.Block;
const Hash32 = types.Hash32;
const Address = types.Address;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const fmtSliceHexLower = std.fmt.fmtSliceHexLower;
const assert = std.debug.assert;

const empty_hash = common.comptimeHexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

pub const VM = struct {
    const vmlog = std.log.scoped(.vm);

    allocator: Allocator,
    env: Environment,
    evm: *EVM,

    // init creates a new EVM VM instance. The caller must call deinit() when done.
    pub fn init(allocator: Allocator, env: Environment) !VM {
        return .{
            .allocator = allocator,
            .env = env,
            .evm = try EVM.init(),
        };
    }

    // deinit destroys a VM instance.
    pub fn deinit(self: *VM) void {
        if (self.evm.*.destroy) |destroy| {
            destroy(self.evm);
        }
    }

    // processMessageCall executes a message call.
    pub fn processMessageCall(self: *VM, msg: Message) !MessageCallOutput {
        const evmc_message = if (msg.target) |target| blk: {
            const evmc_message: evmc.struct_evmc_message = .{
                .kind = evmc.EVMC_CALL,
                .flags = 0,
                .depth = 0,
                .gas = @intCast(msg.gas),
                .recipient = toEVMCAddress(target),
                .sender = toEVMCAddress(msg.sender),
                .input_data = msg.data.ptr,
                .input_size = msg.data.len,
                .value = blk2: {
                    var tx_value: [32]u8 = undefined;
                    std.mem.writeInt(u256, &tx_value, msg.value, .big);
                    break :blk2 .{ .bytes = tx_value };
                },
                .create2_salt = undefined, // EVMC docs: field only mandatory for CREATE2 kind which doesn't apply at depth 0.
                .code_address = toEVMCAddress(msg.target),
            };

            try self.env.state.incrementNonce(msg.sender);

            break :blk evmc_message;
        } else blk: {
            break :blk evmc.struct_evmc_message{
                .kind = evmc.EVMC_CREATE,
                .flags = 0,
                .depth = 0,
                .gas = @intCast(msg.gas),
                .recipient = .{
                    .bytes = blk2: {
                        const sender_nonce: u64 = @intCast(self.env.state.getAccount(msg.sender).nonce);
                        break :blk2 common.computeCREATEContractAddress(self.allocator, msg.sender, sender_nonce) catch unreachable;
                    },
                },
                .sender = .{ .bytes = msg.sender },
                .input_data = msg.data.ptr,
                .input_size = msg.data.len,
                .value = blk2: {
                    var tx_value: [32]u8 = undefined;
                    std.mem.writeInt(u256, &tx_value, msg.value, .big);
                    break :blk2 .{ .bytes = tx_value };
                },
                .create2_salt = undefined, // EVMC docs: field only mandatory for CREATE2 kind which doesn't apply at depth 0.
                .code_address = toEVMCAddress(msg.target),
            };
        };

        self.evm.execute();
        const result = EVMOneHost.call(@ptrCast(self), @ptrCast(&evmc_message));
        defer {
            if (result.release) |release| release(&result);
        }
        return .{
            .gas_left = @intCast(result.gas_left),
            .refund_counter = @intCast(result.gas_refund),
            .success = result.status_code == evmc.EVMC_SUCCESS,
        };
    }
};

pub const MessageCallOutput = struct {
    success: bool,
    gas_left: u64,
    refund_counter: u64,
    // logs: Union[Tuple[()], Tuple[Log, ...]] TODO
    // accounts_to_delete: AddressKeySet, // TODO (delete?)
};
