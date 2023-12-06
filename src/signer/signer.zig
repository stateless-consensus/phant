const std = @import("std");
const Allocator = std.mem.Allocator;
const ecdsa = @import("../crypto/ecdsa.zig");
const types = @import("../types/types.zig");
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const Txn = types.Txn;
const Hash32 = types.Hash32;
const SignatureValues = types.SignatureValues;
const Address = @import("../types/types.zig").Address;

// TODO: TxnSigner should be generalized to:
// - Only accept correct transactions types depending on the fork we're in.
// - Handle "v" correctly depending on transaction type.
// For now it's a post London signer, and only support 1559 txns.
pub const TxnSigner = struct {
    chain_id: u64,
    ecdsa_signer: ecdsa.Signer,

    pub fn init(chain_id: u64) !TxnSigner {
        return TxnSigner{
            .chain_id = chain_id,
            .ecdsa_signer = try ecdsa.Signer.init(),
        };
    }

    pub fn sign(self: TxnSigner, allocator: Allocator, txn: Txn, privkey: ecdsa.PrivateKey) !SignatureValues {
        const txn_hash = try self.hashTxn(allocator, txn);

        const ecdsa_sig = try self.ecdsa_signer.sign(txn_hash, privkey);
        const r = std.mem.readIntSlice(u256, ecdsa_sig[0..32], std.builtin.Endian.Big);
        const s = std.mem.readIntSlice(u256, ecdsa_sig[32..64], std.builtin.Endian.Big);
        const v = switch (txn) {
            Txn.LegacyTxn => 35 + 2 * self.chain_id + ecdsa_sig[64], // We sign using EIP155 since 2016.
        };
        return .{ .r = r, .s = s, .v = v };
    }

    pub fn get_sender(self: TxnSigner, allocator: Allocator, txn: Txn) !Address {
        const txn_hash = try self.hashTxn(allocator, txn);

        const txn_sig = txn.getSignature();
        var sig: ecdsa.Signature = undefined;
        std.mem.writeIntSlice(u256, sig[0..32], txn_sig.r, std.builtin.Endian.Big);
        std.mem.writeIntSlice(u256, sig[32..64], txn_sig.s, std.builtin.Endian.Big);

        sig[64] = switch (txn) {
            Txn.LegacyTxn => blk: {
                if (txn_sig.v == 27 or txn_sig.v == 28) {
                    break :blk @intCast(txn_sig.v - 27);
                }
                const v_eip155 = 35 + 2 * self.chain_id;
                if (txn_sig.v != v_eip155 and txn_sig.v != v_eip155 + 1) {
                    return error.EIP155_v;
                }
                break :blk @intCast(txn_sig.v - v_eip155);
            },
        };

        const pubkey = try self.ecdsa_signer.erecover(sig, txn_hash);
        return hasher.keccak256(pubkey[1..])[12..].*;
    }

    fn hashTxn(self: TxnSigner, allocator: Allocator, transaction: Txn) !Hash32 {
        return switch (transaction) {
            Txn.LegacyTxn => |txn| blk: {
                // Sign using EIP-155 (since ~Nov 2016).
                const legacyTxnRLP = struct {
                    nonce: u64,
                    gas_price: u256,
                    gas_limit: u64,
                    to: ?Address,
                    value: u256,
                    data: []const u8,
                    chain_id: u64,
                    zero1: u8 = 0,
                    zero2: u8 = 0,
                };

                var out = std.ArrayList(u8).init(allocator);
                defer out.deinit();

                try rlp.serialize(legacyTxnRLP, allocator, .{
                    .nonce = txn.nonce,
                    .gas_price = txn.gas_price,
                    .gas_limit = txn.gas_limit,
                    .to = txn.to,
                    .value = txn.value,
                    .data = txn.data,
                    .chain_id = self.chain_id,
                }, &out);

                break :blk hasher.keccak256(out.items);
            },
        };
    }
};

// TODO: tests from mainnet
