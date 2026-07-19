//! IRC Client implementation with TLS support.
//! This module provides an IRC client that can connect, authenticate, and send messages.
const std = @import("std");
const tls = @import("tls");

const utils = @import("utils.zig");
pub const Message = @import("message.zig").Message;
pub const ProtoMessage = @import("message.zig").ProtoMessage;

const default_port = 6667;
const delimiter = "\r\n";
const max_msg_len = 512;

/// Represents an IRC client.
pub const Client = struct {
    alloc: std.mem.Allocator,
    threaded: std.Io.Threaded,
    io: std.Io,
    stream: std.Io.net.Stream,
    connection: tls.Connection,
    tls_input_buf: [tls.input_buffer_len]u8,
    tls_output_buf: [tls.output_buffer_len]u8,
    tls_reader: std.Io.net.Stream.Reader,
    tls_writer: std.Io.net.Stream.Writer,
    tls_rng_source: std.Random.IoSource,
    replies: std.ArrayList(Message),
    incoming: std.ArrayList(Message),
    mutex: std.Io.Mutex,
    cond: std.Io.Condition,
    cfg: Config,

    /// Configuration for the IRC client.
    pub const Config = struct {
        user: []const u8,
        nick: []const u8,
        real_name: []const u8,
        server: []const u8,
        port: ?u16,
        tls: bool = false,
        channels: [][]const u8,
    };

    /// Configuration for the main loop of the IRC client.
    const LoopConfig = struct {
        fn defaultSpawnThread(_: Message) bool {
            return false;
        }

        msg_callback: ?fn (Message) ?Message = null,
        spawn_thread: fn (Message) bool = defaultSpawnThread,
    };

    /// Error set for the Client struct.
    pub const ClientError = error{
        ConnectionFailed,
        MemoryAllocationFailed,
        NetworkReadFailed,
        NetworkWriteFailed,
        ThreadSpawnFailed,
        TlsHandshakeFailed,
    };

    /// Initializes a new IRC client.
    ///
    /// - `alloc`: Memory allocator.
    /// - `cfg`: Client configuration.
    ///
    /// Returns: A new `Client` instance or an error.
    pub fn init(alloc: std.mem.Allocator, cfg: Config) ClientError!Client {
        var client: Client = .{
            .alloc = alloc,
            .threaded = .init_single_threaded,
            .io = undefined,
            .stream = undefined,
            .connection = undefined,
            .tls_input_buf = undefined,
            .tls_output_buf = undefined,
            .tls_reader = undefined,
            .tls_writer = undefined,
            .tls_rng_source = undefined,
            .replies = std.ArrayList(Message).empty,
            .incoming = std.ArrayList(Message).empty,
            .mutex = .init,
            .cond = .init,
            .cfg = cfg,
        };
        client.io = client.threaded.io();
        return client;
    }

    /// Deinitializes the client, freeing resources.
    pub fn deinit(self: *Client) void {
        self.disconnect();
        self.replies.deinit(self.alloc);
        self.incoming.deinit(self.alloc);
    }

    /// Establishes a connection to the IRC server.
    pub fn connect(self: *Client) ClientError!void {
        const host = std.Io.net.HostName.init(self.cfg.server) catch |err| {
            utils.debug("Invalid hostname: {}\n", .{err});
            return ClientError.ConnectionFailed;
        };
        const port = self.cfg.port orelse default_port;

        self.stream = host.connect(self.io, port, .{ .mode = .stream }) catch |err| {
            utils.debug("Connection failed: {}\n", .{err});
            return ClientError.ConnectionFailed;
        };

        if (self.cfg.tls) {
            var root_ca = tls.config.cert.fromSystem(self.alloc, self.io) catch |err| {
                utils.debug("Could not get root CA: {}", .{err});
                return ClientError.TlsHandshakeFailed;
            };
            defer root_ca.deinit(self.alloc);
            self.tls_rng_source = std.Random.IoSource{ .io = self.io };
            self.tls_reader = self.stream.reader(self.io, &self.tls_input_buf);
            self.tls_writer = self.stream.writer(self.io, &self.tls_output_buf);
            self.connection = tls.client(&self.tls_reader.interface, &self.tls_writer.interface, .{
                .host = self.cfg.server,
                .root_ca = root_ca,
                .rng = self.tls_rng_source.interface(),
                .now = std.Io.Clock.real.now(self.io),
            }) catch |err| {
                utils.debug("TLS handshake failed: {}", .{err});
                return ClientError.TlsHandshakeFailed;
            };
        }
        utils.debug("Connected\n", .{});
    }

    /// Disconnects from the IRC server.
    pub fn disconnect(self: *Client) void {
        if (self.cfg.tls) {
            self.connection.close() catch |err| {
                utils.debug("Could not close connection: {}\n", .{err});
                return;
            };
        }
        self.stream.close(self.io);
        utils.debug("Disconnected\n", .{});
    }

    /// Sends a PONG response to the server.
    ///
    /// - `id`: PING message id.
    fn pong(self: *Client, id: []const u8) ClientError!void {
        try self.sendCommand("PONG :{s}{s}", .{ id, delimiter });
    }

    // Sends PASS for servers with password protection
    //
    // - `pass`: Password to the server
    pub fn pass(self: *Client, passwd: []const u8) ClientError!void {
        try self.sendCommand("PASS {s}{s}", .{ passwd, delimiter });
    }

    /// Registers the client with the IRC server.
    pub fn register(self: *Client) ClientError!void {
        try self.sendCommand("NICK {s}{s}USER {s} * * :{s}{s}", .{
            self.cfg.nick,
            delimiter,
            self.cfg.user,
            self.cfg.real_name,
            delimiter,
        });
    }

    /// Changes the nickname of the client.
    ///
    /// - `nickname`: New nickname.
    /// - `hopcount`: Optional hop count value.
    pub fn nick(self: *Client, nickname: []const u8, hopcount: ?u8) ClientError!void {
        if (hopcount) |hopcount_val| {
            try self.sendCommand("NICK {s} {d}{s}", .{ nickname, hopcount_val, delimiter });
        } else {
            try self.sendCommand("NICK {s}{s}", .{ nickname, delimiter });
        }
    }

    /// Joins an IRC channel.
    ///
    /// - `channels`: channel(s) to join.
    pub fn join(self: *Client, channels: []const u8) ClientError!void {
        try self.sendCommand("JOIN {s}{s}", .{ channels, delimiter });
    }

    /// Sends a notice message to a user or channel.
    ///
    /// - `targets`: Target user(s) or channel(s).
    /// - `text`: Message content.
    pub fn notice(self: *Client, targets: []const u8, text: []const u8) ClientError!void {
        try self.sendCommand("NOTICE {s} :{s}{s}", .{ targets, text, delimiter });
    }

    /// Leaves an IRC channel.
    ///
    /// - `channels`: Channel(s) to leave.
    /// - `reason`: Optional reason for leaving.
    pub fn part(self: *Client, channels: []const u8, reason: ?[]const u8) ClientError!void {
        try self.sendCommand("PART {s} :{s}{s}", .{ channels, reason orelse "", delimiter });
    }

    /// Sends a private message to a user or channel.
    ///
    /// - `targets`: Target user(s) or channel(s).
    /// - `text`: Message content.
    pub fn privmsg(self: *Client, targets: []const u8, text: []const u8) ClientError!void {
        try self.sendCommand("PRIVMSG {s} :{s}{s}", .{ targets, text, delimiter });
    }

    /// Quits the IRC server.
    ///
    /// - `reason`: Optional reason for quiting.
    pub fn quit(self: *Client, reason: ?[]const u8) ClientError!void {
        try self.sendCommand("QUIT :{s}{s}", .{ reason orelse "", delimiter });
    }

    /// Gets or sets the topic of a channel.
    ///
    /// - `text`: Optional topic to set.
    pub fn topic(self: *Client, channel: []const u8, text: ?[]const u8) ClientError!void {
        if (text != null and !std.mem.eql(u8, text.?, "")) {
            try self.sendCommand("TOPIC {s} :{s}{s}", .{ channel, text.?, delimiter });
        } else {
            try self.sendCommand("TOPIC {s}{s}", .{ channel, delimiter });
        }
    }

    fn sendCommand(self: *Client, comptime cmd_fmt: []const u8, args: anytype) ClientError!void {
        const raw_msg = std.fmt.allocPrint(self.alloc, cmd_fmt, args) catch |err| {
            utils.debug("Memory allocation failed: {}", .{err});
            return ClientError.MemoryAllocationFailed;
        };
        defer self.alloc.free(raw_msg);

        if (self.cfg.tls) {
            self.connection.writeAll(raw_msg) catch |err| {
                utils.debug("Network write failed: {}", .{err});
                return ClientError.NetworkWriteFailed;
            };
        } else {
            var write_buf: [max_msg_len]u8 = undefined;
            var writer = self.stream.writer(self.io, &write_buf);
            writer.interface.writeAll(raw_msg) catch |err| {
                utils.debug("Network write failed: {}", .{err});
                return ClientError.NetworkWriteFailed;
            };
            writer.interface.flush() catch |err| {
                utils.debug("Network flush failed: {}", .{err});
                return ClientError.NetworkWriteFailed;
            };
        }
    }

    fn msgCallbackWorker(self: *Client, msg: Message, msg_callback: fn (Message) ?Message) ClientError!void {
        const reply = msg_callback(msg) orelse return;
        self.mutex.lock(self.io) catch |err| {
            utils.debug("Mutex lock failed: {}", .{err});
            return;
        };
        self.replies.append(self.alloc, reply) catch |err| {
            self.mutex.unlock(self.io);
            utils.debug("Memory allocation failed: {}", .{err});
            return ClientError.MemoryAllocationFailed;
        };
        self.mutex.unlock(self.io);
        self.cond.signal(self.io);
    }

    fn handleMessage(self: *Client, raw_msg: []const u8, loop_config: LoopConfig) ClientError!void {
        if (raw_msg.len < 4) {
            return;
        }

        // Handle the PING messages ourselves.
        if (std.mem.eql(u8, raw_msg[0..4], "PING")) {
            const index = std.mem.find(u8, raw_msg, ":").?;
            const id = raw_msg[index + 1 ..];
            try self.pong(id);
            return;
        }

        // Auto-join the configured channels.
        if (std.mem.find(u8, raw_msg, " 376 ")) |_| {
            for (self.cfg.channels) |channel| {
                try self.join(channel);
            }
        }

        // Otherwise parse the raw_msg into a ProtoMessage and Message.
        // Spawn a thread to handle the message using msg_callback.
        // Detach the thread so that it takes care of cleanup itself.
        var proto_msg = ProtoMessage.parse(raw_msg) catch return;
        utils.debug("Command: {}\n", .{proto_msg.command});
        const msg = proto_msg.toMessage() orelse return;
        if (loop_config.msg_callback) |msg_callback| {
            if (loop_config.spawn_thread(msg)) {
                const thread = std.Thread.spawn(.{}, msgCallbackWorker, .{ self, msg, msg_callback }) catch |err| {
                    utils.debug("Thread spawn failed: {}", .{err});
                    return ClientError.ThreadSpawnFailed;
                };
                utils.debug("Started message callback worker thread\n", .{});
                thread.detach();
            } else {
                self.msgCallbackWorker(msg, msg_callback) catch |err| {
                    utils.debug("Thread spawn failed: {}", .{err});
                    return ClientError.ThreadSpawnFailed;
                };
            }
        } else {
            self.mutex.lock(self.io) catch |err| {
                utils.debug("Mutex lock failed: {}", .{err});
                return;
            };
            self.incoming.append(self.alloc, msg) catch |err| {
                utils.debug("Allocating message to incoming queue failed: {}", .{err});
                return ClientError.MemoryAllocationFailed;
            };
            // no cond signal, that is for writer loop
            self.mutex.unlock(self.io);
        }
    }

    /// The main event loop for reading messages.
    ///
    /// - `loop_config`: Main event loop configuration.
    pub fn loop(self: *Client, loop_config: LoopConfig) ClientError!void {
        const thread = std.Thread.spawn(.{}, writeLoop, .{self}) catch |err| {
            utils.debug("Thread spawn failed: {}", .{err});
            return ClientError.ThreadSpawnFailed;
        };
        thread.detach();
        try self.readLoop(loop_config);
    }

    fn getNextMessage(self: *Client) ClientError!?[]const u8 {
        var read_buf: [max_msg_len]u8 = undefined;
        const reader = if (self.cfg.tls) tls: {
            const tls_reader = self.connection.reader(&read_buf);
            break :tls &tls_reader.interface;
        } else plain: {
            const plain_reader = self.stream.reader(self.io, &read_buf);
            break :plain &plain_reader.interface;
        };
        const raw_msg_with_nl = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => {
                utils.debug("Connection Closed\n", .{});
                return null;
            },
            else => {
                utils.debug("Network read failed: {}\n", .{err});
                return ClientError.NetworkReadFailed;
            },
        };
        if (raw_msg_with_nl.len == 0) {
            utils.debug("Connection Closed\n", .{});
            return null;
        }
        const raw_msg = raw_msg_with_nl[0 .. raw_msg_with_nl.len - 1];
        return raw_msg;
    }

    /// Reads messages from the server and processes them.
    ///
    /// - `loop_config`: Main event loop configuration.
    fn readLoop(self: *Client, loop_config: LoopConfig) ClientError!void {
        while (try self.getNextMessage()) |msg| {
            try self.handleMessage(msg, loop_config);
        }
        return;
    }

    // Dequeue N incoming messages into dst arrayList.
    // Dst should be empty or it will leak memory
    //
    // - `dst`: Destination arrayList
    // - `n`: Max number of incoming messages to dequeue. If null, dequeue all
    pub fn dequeue_incoming(self: *Client, dst: *std.ArrayList(Message), n: ?usize) void {
        const items_to_dequeue = if (n) |limit|
            @min(limit, self.incoming.items.len)
        else
            self.incoming.items.len;
        std.debug.assert(items_to_dequeue <= dst.capacity);
        dst.clearRetainingCapacity();
        dst.appendSliceAssumeCapacity(self.incoming.items[0..items_to_dequeue]);
        const remaining = self.incoming.items.len - items_to_dequeue;
        @memmove(self.incoming.items[0..remaining], self.incoming.items[items_to_dequeue..]);
        self.incoming.shrinkRetainingCapacity(remaining);
    }

    /// Writes callback reply messages to the server.
    fn writeLoop(self: *Client) ClientError!void {
        while (true) {
            self.mutex.lock(self.io) catch |err| {
                utils.debug("Mutex lock failed: {}", .{err});
                return;
            };
            defer self.mutex.unlock(self.io);

            if (self.replies.items.len > 0) {
                const reply = self.replies.pop() orelse return;

                switch (reply) {
                    .NICK => |args| {
                        try self.nick(args.nickname, args.hopcount);
                    },
                    .NOTICE => |args| {
                        try self.notice(args.targets, args.text);
                    },
                    .PRIVMSG => |args| {
                        try self.privmsg(args.targets, args.text);
                    },
                    .JOIN => |args| {
                        try self.join(args.channels);
                    },
                    .PART => |args| {
                        try self.part(args.channels, args.reason);
                    },
                    .QUIT => |args| {
                        try self.quit(args.reason);
                    },
                    .TOPIC => |args| {
                        try self.topic(args.channel, args.text);
                    },
                    else => {
                        utils.debug("Unsupported message type\n", .{});
                    },
                }
            } else {
                self.cond.wait(self.io, &self.mutex) catch |err| {
                    utils.debug("Condition wait failed: {}", .{err});
                    return;
                };
            }
        }
    }
};
