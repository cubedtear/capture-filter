const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const netparser = @import("netparser");
const zgui = @import("zgui");
const zglfw = @import("zglfw");
const zgpu = @import("zgpu");

const mmapped_file = @import("mmapped_file.zig");

const Surface = struct {
    gctx: *zgpu.GraphicsContext,
    window: *zglfw.Window,
    default_font: zgui.Font,

    const Self = @This();

    pub fn init(alloc: Allocator) !Surface {
        try zglfw.init();

        zglfw.windowHintTyped(.client_api, .no_api);

        const window = try zglfw.Window.create(1600, 1000, "Title", null);
        errdefer window.destroy();
        window.setSizeLimits(400, 400, -1, -1);

        zgui.init(alloc);

        zgui.io.setConfigFlags(.{
            .dock_enable = true,
            .viewport_enable = true,
        });

        const content_dir = "res/";
        const default_font = zgui.io.addFontFromFile(content_dir ++ "Roboto-Medium.ttf", 16.0);

        const gctx = try zgpu.GraphicsContext.create(
            alloc,
            .{
                .window = window,
                .fn_getTime = @ptrCast(&zglfw.getTime),
                .fn_getFramebufferSize = @ptrCast(&zglfw.Window.getFramebufferSize),
                .fn_getWin32Window = @ptrCast(&zglfw.getWin32Window),
                .fn_getX11Display = @ptrCast(&zglfw.getX11Display),
                .fn_getX11Window = @ptrCast(&zglfw.getX11Window),
                .fn_getWaylandDisplay = @ptrCast(&zglfw.getWaylandDisplay),
                .fn_getWaylandSurface = @ptrCast(&zglfw.getWaylandWindow),
                .fn_getCocoaWindow = @ptrCast(&zglfw.getCocoaWindow),
            },
            .{
                .present_mode = .fifo, // Note: change to .immediate to disable vsync.
            },
        );
        errdefer gctx.destroy(alloc);

        zgui.backend.init(
            window,
            gctx.device,
            @intFromEnum(zgpu.GraphicsContext.swapchain_format),
            @intFromEnum(zgpu.wgpu.TextureFormat.undef),
        );
        zgui.io.setDefaultFont(default_font);

        return .{
            .gctx = gctx,
            .window = window,
            .default_font = default_font,
        };
    }

    pub fn deinit(self: *Self, alloc: *Allocator) void {
        zglfw.terminate();
        self.gctx.destroy(alloc);
        self.window.destroy();
    }

    pub fn present(self: *Self) void {
        const swapchain_texv = self.gctx.swapchain.getCurrentTextureView();
        defer swapchain_texv.release();

        const commands = commands: {
            const encoder = self.gctx.device.createCommandEncoder(null);
            defer encoder.release();

            // Gui pass.
            {
                const pass = zgpu.beginRenderPassSimple(encoder, .load, swapchain_texv, null, null, null);
                defer zgpu.endReleasePass(pass);
                zgui.backend.draw(pass);
            }

            break :commands encoder.finish(null);
        };
        defer commands.release();

        self.gctx.submit(&.{commands});
        _ = self.gctx.present();
    }
};

pub fn main() !void {
    const startup_instant = try std.time.Instant.now();

    var gpa = std.heap.GeneralPurposeAllocator(.{
        // .stack_trace_frames = 20,
        // .retain_metadata = true,
        // .verbose_log = true,
    }){};
    // var logging_gpa = std.heap.loggingAllocator(gpa.allocator());
    // const alloc = logging_gpa.allocator();
    const alloc = gpa.allocator();

    const input_file_path = blk: {
        var args = try std.process.argsWithAllocator(alloc);
        defer args.deinit();

        _ = args.skip(); // Skip the executable name.

        const arg = args.next() orelse return std.debug.panic("Missing input file path.\n", .{});

        break :blk try alloc.dupe(u8, arg);
    };
    defer alloc.free(input_file_path);

    std.log.info("[capture-filter] Input file path: {s}", .{input_file_path});

    const file_data = mmapped_file.map_file(input_file_path) catch |err| {
        return std.debug.panic("Failed to map file: {}\n", .{err});
    };

    // Convert file_data.len from bytes to the appropriate unit (KiB, MiB, GiB, etc.), such that the unit is the largest possible without exceeding 1024.
    const file_size_str = blk: {
        const KiB = 1024;
        const MiB = KiB * 1024;
        const GiB = MiB * 1024;
        const TiB = GiB * 1024;

        if (file_data.len > TiB) {
            break :blk try std.fmt.allocPrint(alloc, "{d:.2} TiB", .{@as(f64, @floatFromInt(file_data.len)) / TiB});
        } else if (file_data.len > GiB) {
            break :blk try std.fmt.allocPrint(alloc, "{d:.2} GiB", .{@as(f64, @floatFromInt(file_data.len)) / GiB});
        } else if (file_data.len > MiB) {
            break :blk try std.fmt.allocPrint(alloc, "{d:.2} MiB", .{@as(f64, @floatFromInt(file_data.len)) / MiB});
        } else if (file_data.len > KiB) {
            break :blk try std.fmt.allocPrint(alloc, "{d:.2} KiB", .{@as(f64, @floatFromInt(file_data.len)) / KiB});
        } else {
            break :blk try std.fmt.allocPrint(alloc, "{} B", .{file_data.len});
        }
    };
    defer alloc.free(file_size_str);

    std.log.info("[capture-filter] Loaded file size: {s}\n", .{file_size_str});

    if (file_data.len < netparser.pcapng.PcapngParser.min_file_size) {
        return std.debug.panic("File is too small to contain a Section Header Block Header.\n", .{});
    }

    var parser = netparser.pcapng.PcapngParser.init(file_data);

    var section_interface_list = std.ArrayList(std.ArrayList(netparser.pcapng.InterfaceDescriptionBlock)).init(alloc);
    defer {
        for (section_interface_list.items) |interfaces| {
            interfaces.deinit();
        }
        section_interface_list.deinit();
    }

    const PacketData = struct {
        packet_index: usize,
        block_data: []u8,
        interfaces_list_index: usize,
    };

    var packet_list = std.ArrayList(PacketData).init(alloc);
    defer packet_list.deinit();

    var i: u64 = 0;
    while (true) {
        const block_slice = parser.get_next_block_slice() orelse break;

        if (block_slice.block_type == netparser.pcapng.BlockType.InterfaceDescriptionBlock) {
            const idb_block = try parser.parse_block_slice(block_slice.slice) orelse continue;
            try section_interface_list.items[section_interface_list.items.len - 1].append(idb_block.body.InterfaceDescriptionBlock);
        }

        if (block_slice.block_type == netparser.pcapng.BlockType.SectionHeaderBlock) {
            try section_interface_list.append(std.ArrayList(netparser.pcapng.InterfaceDescriptionBlock).init(alloc));
            // Parse the Section Header Block options, which sets the endian on the parser. Ignore the result.
            _ = try parser.parse_block_slice(block_slice.slice) orelse continue;
        }

        if (block_slice.block_type == netparser.pcapng.BlockType.EnhancedPacketBlock) {
            try packet_list.append(.{
                .packet_index = i,
                .block_data = block_slice.slice,
                .interfaces_list_index = section_interface_list.items.len - 1,
            });
        }

        i += 1;
    }

    var imgui_gpa = std.heap.GeneralPurposeAllocator(.{
        // .stack_trace_frames = 20,
        // .retain_metadata = true,
        // .verbose_log = true,
    }){};
    // var imgui_logging_gpa = std.heap.loggingAllocator(imgui_gpa.allocator());
    // const imgui_alloc = imgui_logging_gpa.allocator();
    const imgui_alloc = imgui_gpa.allocator();

    std.log.info("[capture-filter] Total blocks in PCAPNG: {}\n", .{i});

    var surface = try Surface.init(imgui_alloc);

    var filter_buffer = [_:0]u8{0} ** 1024;
    var filter_initialized = false;

    var filtered_packets = std.ArrayList(usize).init(alloc);
    defer filtered_packets.deinit();

    var selected_packet_index_opt: ?usize = null;

    const startup_end_instant = try std.time.Instant.now();
    std.log.info("[capture-filter] Initialization took: {d:.2}s", .{ @as(f64, @floatFromInt(startup_end_instant.since(startup_instant))) / 1_000_000_000.0 });

    while (!surface.window.shouldClose() and surface.window.getKey(.escape) != .press) {
        if (surface.window.getKey(.space) == .press) {
            _ = imgui_gpa.detectLeaks();
        }

        zglfw.pollEvents();

        const fb_width = surface.gctx.swapchain_descriptor.width;
        const fb_height = surface.gctx.swapchain_descriptor.height;

        zgui.backend.newFrame(fb_width, fb_height);

        _ = zgui.DockSpaceOverViewport(zgui.getStrId("MainDockspace"), zgui.getMainViewport(), .{
            .passthru_central_node = true,
        });

        // Useful to debug the GUI
        // zgui.showMetricsWindow(null);
        zgui.showDemoWindow(null);

        var window_title_buffer = [_]u8{0} ** 1024;
        const window_title: [:0]u8 = try std.fmt.bufPrintZ(&window_title_buffer, "Capture Filter - Frame time: {d:.0} ms/frame - FPS: {d:.0}", .{ 1000.0 / zgui.io.getFramerate(), zgui.io.getFramerate() });
        surface.window.setTitle(window_title);

        // Packet list window
        {
            const packet_list_window_visible = zgui.begin("Packet list", .{
                .flags = .{
                    .no_collapse = true,
                },
            });
            defer zgui.end();

            if (packet_list_window_visible) {
                zgui.alignTextToFramePadding();
                zgui.text("Filter:", .{});
                zgui.sameLine(.{});
                const filter_dirty = zgui.inputText("##filter", .{
                    .buf = filter_buffer[0..],
                    .flags = .{},
                    .callback = null,
                });

                const filter_str_slice = std.mem.span(@as([*:0]u8, filter_buffer[0..]));

                if (filter_dirty or !filter_initialized) {
                    filter_initialized = true;

                    std.log.info("[capture-filter] Applying filter: '{s}'", .{filter_str_slice});
                    filtered_packets.clearRetainingCapacity();
                    for (packet_list.items, 0..) |*packet, packet_index| {
                        if (filter_str_slice.len == 0) {
                            try filtered_packets.append(packet_index);
                            continue;
                        }

                        const epb_block = try parser.parse_block_slice(packet.block_data) orelse continue;

                        const epb = epb_block.body.EnhancedPacketBlock;

                        const epb_ipb = section_interface_list.items[packet.interfaces_list_index].items[epb.interface_id];
                        const link_type = epb_ipb.link_type;

                        var fbs = std.io.fixedBufferStream(epb.packet_data);
                        var bit_reader = netparser.utils.bit_reader.bitReader(.big, fbs.reader().any());

                        var link_layer_payload: netparser.link.LinkLayerPayload = switch (link_type) {
                            .ETHERNET => if (netparser.link.EthernetLinkType.parse(&bit_reader, alloc)) |ethernet| blk: {
                                break :blk .{ .Ethernet = ethernet };
                            } else |err| {
                                std.debug.print("Failed to parse Ethernet link layer for packet #{}: {}\n", .{ packet_list.items.len, err });
                                // TODO: Implement IP defragmentation.
                                continue;
                            },
                            .NULL => if (netparser.link.NullLinkType.parse(&bit_reader, alloc)) |null_packet| blk: {
                                break :blk .{ .Null = null_packet };
                            } else |err| {
                                std.debug.print("Failed to parse Null link layer for packet #{}: {}\n", .{ packet_list.items.len, err });
                                // TODO: Implement IP defragmentation.
                                continue;
                            },
                            else => {
                                std.debug.print("Unknown link type: {}\n", .{link_type});
                                continue;
                            },
                        };
                        defer link_layer_payload.deinit(alloc);

                        var packet_layers = [_:0]u8{0} ** 1024;
                        try get_packet_layers(&link_layer_payload, packet_layers[0..]);

                        var packet_src_addr = [_:0]u8{0} ** 1024;
                        try get_packet_src_addr(&link_layer_payload, packet_src_addr[0..]);

                        var packet_dst_addr = [_:0]u8{0} ** 1024;
                        try get_packet_dst_addr(&link_layer_payload, packet_dst_addr[0..]);

                        const skip_packet =
                            std.mem.indexOf(u8, &packet_layers, filter_str_slice) == null and
                            std.mem.indexOf(u8, &packet_src_addr, filter_str_slice) == null and
                            std.mem.indexOf(u8, &packet_dst_addr, filter_str_slice) == null;

                        if (!skip_packet) {
                            try filtered_packets.append(packet_index);
                        }
                    }
                    std.log.info("[capture-filter] Filter applied.", .{});
                }

                const table_visible = zgui.beginTable("table", .{
                    .column = 6,
                    .flags = .{
                        .row_bg = true,
                        .borders = .{
                            .inner_v = true,
                            .outer_h = true,
                        },
                        .no_borders_in_body = true,
                        .resizable = true,
                        .scroll_x = true,
                        .scroll_y = true,
                        .highlight_hovered_column = true,
                    },
                });
                if (table_visible) {
                    defer zgui.endTable();

                    zgui.tableSetupScrollFreeze(0, 1);

                    zgui.tableSetupColumn("#", .{});
                    zgui.tableSetupColumn("Layers", .{});
                    zgui.tableSetupColumn("Src. addr.", .{});
                    zgui.tableSetupColumn("Dst. addr.", .{});
                    zgui.tableSetupColumn("Src. port", .{});
                    zgui.tableSetupColumn("Dst. port", .{});

                    zgui.tableSetupScrollFreeze(1, 1);

                    zgui.tableHeadersRow();

                    var clipper = zgui.ListClipper.init();
                    clipper.begin(@intCast(filtered_packets.items.len), null);
                    defer clipper.end();

                    while (clipper.step()) {
                        for (@intCast(clipper.DisplayStart)..@intCast(clipper.DisplayEnd)) |filtered_packet_index| {
                            const packet_index = filtered_packets.items[filtered_packet_index];
                            const packet_data = packet_list.items[packet_index];

                            const epb_block = try parser.parse_block_slice(packet_data.block_data) orelse continue;

                            const epb = epb_block.body.EnhancedPacketBlock;

                            const epb_ipb = section_interface_list.items[packet_data.interfaces_list_index].items[epb.interface_id];
                            const link_type = epb_ipb.link_type;

                            var fbs = std.io.fixedBufferStream(epb.packet_data);
                            var bit_reader = netparser.utils.bit_reader.bitReader(.big, fbs.reader().any());

                            var link_layer_payload: netparser.link.LinkLayerPayload = switch (link_type) {
                                .ETHERNET => if (netparser.link.EthernetLinkType.parse(&bit_reader, alloc)) |ethernet| blk: {
                                    break :blk .{ .Ethernet = ethernet };
                                } else |err| {
                                    std.debug.print("Failed to parse Ethernet link layer for packet #{}: {}\n", .{ packet_list.items.len, err });
                                    // TODO: Implement IP defragmentation.
                                    continue;
                                },
                                .NULL => if (netparser.link.NullLinkType.parse(&bit_reader, alloc)) |null_packet| blk: {
                                    break :blk .{ .Null = null_packet };
                                } else |err| {
                                    std.debug.print("Failed to parse Null link layer for packet #{}: {}\n", .{ packet_list.items.len, err });
                                    // TODO: Implement IP defragmentation.
                                    continue;
                                },
                                else => {
                                    std.debug.print("Unknown link type: {}\n", .{link_type});
                                    continue;
                                },
                            };
                            defer link_layer_payload.deinit(alloc);

                            const packet = &link_layer_payload;

                            var packet_layers = [_:0]u8{0} ** 1024;
                            try get_packet_layers(packet, packet_layers[0..]);

                            var packet_src_addr = [_:0]u8{0} ** 1024;
                            try get_packet_src_addr(packet, packet_src_addr[0..]);

                            var packet_dst_addr = [_:0]u8{0} ** 1024;
                            try get_packet_dst_addr(packet, packet_dst_addr[0..]);

                            const packet_src_port: ?u16 = try get_source_port_from_link_layer_payload(packet);
                            const packet_dst_port: ?u16 = try get_dest_port_from_link_layer_payload(packet);

                            zgui.tableNextRow(.{});

                            const selectable_cell_flags: zgui.SelectableFlags = .{ .span_all_columns = true, .allow_overlap = true };

                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    const was_selected = selected_packet_index_opt == packet_index;
                                    const selected = zgui.selectable(zgui.formatZ("{}", .{packet_index}), .{ .selected = was_selected, .flags = selectable_cell_flags });
                                    if (selected) {
                                        selected_packet_index_opt = packet_index;
                                    }
                                }
                            }

                            // Layers
                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    zgui.textUnformatted(std.mem.span(@as([*:0]u8, packet_layers[0..])));
                                }
                            }

                            // Source address
                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    zgui.textUnformatted(std.mem.span(@as([*:0]u8, packet_src_addr[0..])));
                                }
                            }

                            // Destination address
                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    zgui.textUnformatted(std.mem.span(@as([*:0]u8, packet_dst_addr[0..])));
                                }
                            }

                            // Source port
                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    if (packet_src_port) |port| {
                                        zgui.text("{?}", .{port});
                                    } else {
                                        zgui.textUnformatted("-");
                                    }
                                }
                            }

                            // Destination port
                            {
                                const col_visible = zgui.tableNextColumn();
                                if (col_visible) {
                                    if (packet_dst_port) |port| {
                                        zgui.text("{?}", .{port});
                                    } else {
                                        zgui.textUnformatted("-");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Packet detail window
        {
            const packet_detail_window_visible = zgui.begin("Packet detail", .{
                .flags = .{
                    .no_collapse = true,
                },
            });
            defer zgui.end();

            if (packet_detail_window_visible) {}
        }

        // Packet bytes window
        {
            const packet_bytes_window_visible = zgui.begin("Packet bytes", .{
                .flags = .{
                    // .no_collapse = false, // Allow collapsing
                },
            });
            defer zgui.end();

            if (packet_bytes_window_visible) {
                if (selected_packet_index_opt) |selected_packet_index| {
                    const packet_data = packet_list.items[selected_packet_index];

                    const table_visible = zgui.beginTable("table", .{
                        .column = 16,
                        .flags = .{
                            .row_bg = true,
                            .borders = .{
                                .inner_v = true,
                                .outer_h = true,
                            },
                            .no_borders_in_body = true,
                            .resizable = true,
                            .scroll_y = true,
                            .sizing = .fixed_fit,
                        },
                    });
                    if (table_visible) {
                        defer zgui.endTable();

                        zgui.tableSetupScrollFreeze(0, 1);

                        zgui.tableSetupColumn("0", .{});
                        zgui.tableSetupColumn("1", .{});
                        zgui.tableSetupColumn("2", .{});
                        zgui.tableSetupColumn("3", .{});
                        zgui.tableSetupColumn("4", .{});
                        zgui.tableSetupColumn("5", .{});
                        zgui.tableSetupColumn("6", .{});
                        zgui.tableSetupColumn("7", .{});
                        zgui.tableSetupColumn("8", .{});
                        zgui.tableSetupColumn("9", .{});
                        zgui.tableSetupColumn("A", .{});
                        zgui.tableSetupColumn("B", .{});
                        zgui.tableSetupColumn("C", .{});
                        zgui.tableSetupColumn("D", .{});
                        zgui.tableSetupColumn("E", .{});
                        zgui.tableSetupColumn("F", .{});

                        zgui.tableHeadersRow();

                        const epb_block = try parser.parse_block_slice(packet_data.block_data) orelse continue;
                        const epb = epb_block.body.EnhancedPacketBlock;

                        var clipper = zgui.ListClipper.init();
                        const row_count = (epb.packet_data.len + 15) / 16;
                        clipper.begin(@intCast(row_count), null);
                        defer clipper.end();

                        const selectable_cell_flags: zgui.SelectableFlags = .{ .span_all_columns = false };

                        while (clipper.step()) {
                            for (@intCast(clipper.DisplayStart)..@intCast(clipper.DisplayEnd)) |row_index| {
                                zgui.tableNextRow(.{});

                                for (0..16) |byte_in_row| {
                                    const byte_index = row_index * 16 + byte_in_row;
                                    if (byte_index >= epb.packet_data.len) {
                                        break;
                                    }
                                    const byte = epb.packet_data[byte_index];

                                    const col_visible = zgui.tableNextColumn();
                                    if (col_visible) {
                                        const selected = zgui.selectable(zgui.formatZ("{X:0>2}", .{byte}), .{ .flags = selectable_cell_flags });
                                        if (selected) {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        surface.present();
    }
}

fn get_packet_layers(payload: *const netparser.link.LinkLayerPayload, buf: []u8) !void {
    var fbs = std.io.fixedBufferStream(buf);
    try get_layer_col_from_link_layer_payload(payload, fbs.writer().any());
}

fn get_packet_src_addr(payload: *const netparser.link.LinkLayerPayload, buf: []u8) !void {
    var fbs = std.io.fixedBufferStream(buf);
    const addr_written = try get_source_addr_col_from_link_layer_payload(payload, fbs.writer().any());
    if (!addr_written) {
        try fbs.writer().print("-", .{});
    }
}

fn get_packet_dst_addr(payload: *const netparser.link.LinkLayerPayload, buf: []u8) !void {
    var fbs = std.io.fixedBufferStream(buf);
    const addr_written = try get_dest_addr_col_from_link_layer_payload(payload, fbs.writer().any());
    if (!addr_written) {
        try fbs.writer().print("-", .{});
    }
}

fn get_layer_col_from_link_layer_payload(link_layer_payload: *const netparser.link.LinkLayerPayload, writer: std.io.AnyWriter) !void {
    switch (link_layer_payload.*) {
        .Ethernet => |eth_layer| {
            try std.fmt.format(writer, "Ethernet", .{});
            try get_layer_col_from_eth_layer(&eth_layer, writer);
        },
        .Null => |null_layer| {
            try std.fmt.format(writer, "Null", .{});
            try get_layer_col_from_null_layer(&null_layer, writer);
        },
    }
}

fn get_layer_col_from_eth_layer(eth_packet: *const netparser.link.EthernetLinkType, writer: std.io.AnyWriter) !void {
    switch (eth_packet.payload) {
        .IPv4 => |ipv4| {
            try std.fmt.format(writer, " > IPv4", .{});
            try get_layer_col_from_ipv4_6(&ipv4.payload, writer);
        },
        .IPv6 => |ipv6| {
            try std.fmt.format(writer, " > IPv6", .{});
            try get_layer_col_from_ipv4_6(&ipv6.payload, writer);
        },
        .ARP => {
            try std.fmt.format(writer, " > ARP", .{});
        },
        .unknown => {
            try std.fmt.format(writer, " > Unknown", .{});
        },
    }
}

fn get_layer_col_from_null_layer(null_packet: *const netparser.link.NullLinkType, writer: std.io.AnyWriter) !void {
    switch (null_packet.payload) {
        .IPv4 => |ipv4| {
            try std.fmt.format(writer, " > IPv4", .{});
            try get_layer_col_from_ipv4_6(&ipv4.payload, writer);
        },
        .IPv6 => |ipv6| {
            try std.fmt.format(writer, " > IPv6", .{});
            try get_layer_col_from_ipv4_6(&ipv6.payload, writer);
        },
    }
}

fn get_layer_col_from_ipv4_6(ipv4_6_packet: *const netparser.network.IPv4Payload, writer: std.io.AnyWriter) !void {
    switch (ipv4_6_packet.*) {
        .ICMP => {
            try std.fmt.format(writer, " > ICMP", .{});
        },
        .IGMP => {
            try std.fmt.format(writer, " > IGMP", .{});
        },
        .TCP => {
            try std.fmt.format(writer, " > TCP", .{});
        },
        .UDP => {
            try std.fmt.format(writer, " > UDP", .{});
        },
        .IPv6_ICMP => {
            try std.fmt.format(writer, " > IPv6 ICMP", .{});
        },
        .IPv6_HopByHopOpt => {
            try std.fmt.format(writer, " > IPv6 HopByHopOpt - TODO: Show inner-protocol header, not this", .{});
        },
        .IPv6_Route => {
            try std.fmt.format(writer, " > IPv6 Route - TODO: Show inner-protocol header, not this", .{});
        },
        .FragmentedPacket => {
            try std.fmt.format(writer, " > Fragmented IP packet", .{});
        },
    }
}

fn get_source_addr_col_from_link_layer_payload(link_layer_payload: *const netparser.link.LinkLayerPayload, writer: std.io.AnyWriter) !bool {
    switch (link_layer_payload.*) {
        .Ethernet => |eth_layer| {
            return try get_source_addr_col_from_eth_layer(&eth_layer, writer);
        },
        .Null => |null_layer| {
            return try get_source_addr_col_from_null_layer(&null_layer, writer);
        },
    }
}

fn get_source_addr_col_from_eth_layer(eth_packet: *const netparser.link.EthernetLinkType, writer: std.io.AnyWriter) !bool {
    switch (eth_packet.payload) {
        .IPv4 => |ipv4| {
            try format_ipv4_addr(ipv4.source_address, writer);
            return true;
        },
        .IPv6 => |ipv6| {
            try format_ipv6_rfc5952(ipv6.source_address, writer);
            return true;
        },
        .ARP => {
            return false;
        },
        .unknown => {
            return false;
        },
    }
}

fn get_source_addr_col_from_null_layer(null_packet: *const netparser.link.NullLinkType, writer: std.io.AnyWriter) !bool {
    switch (null_packet.payload) {
        .IPv4 => |ipv4| {
            try format_ipv4_addr(ipv4.source_address, writer);
            return true;
        },
        .IPv6 => |ipv6| {
            try format_ipv6_rfc5952(ipv6.source_address, writer);
            return true;
        },
    }
}

fn get_dest_addr_col_from_link_layer_payload(link_layer_payload: *const netparser.link.LinkLayerPayload, writer: std.io.AnyWriter) !bool {
    switch (link_layer_payload.*) {
        .Ethernet => |eth_layer| {
            switch (eth_layer.payload) {
                .IPv4 => |ipv4| {
                    try format_ipv4_addr(ipv4.destination_address, writer);
                    return true;
                },
                .IPv6 => |ipv6| {
                    try format_ipv6_rfc5952(ipv6.destination_address, writer);
                    return true;
                },
                .ARP => {
                    // TODO: Consider printing the ARP target address
                    return false;
                },
                .unknown => {
                    return false;
                },
            }
        },
        .Null => |null_layer| {
            switch (null_layer.payload) {
                .IPv4 => |ipv4| {
                    try format_ipv4_addr(ipv4.destination_address, writer);
                    return true;
                },
                .IPv6 => |ipv6| {
                    try format_ipv6_rfc5952(ipv6.destination_address, writer);
                    return true;
                },
            }
        },
    }
}

fn format_ipv4_addr(ipv4_addr: netparser.network.IPv4Address, writer: std.io.AnyWriter) !void {
    try std.fmt.format(writer, "{}.{}.{}.{}", .{
        ipv4_addr[0],
        ipv4_addr[1],
        ipv4_addr[2],
        ipv4_addr[3],
    });
}

fn format_ipv6_rfc5952(ipv6_addr: netparser.network.IPv6Address, writer: std.io.AnyWriter) !void {
    // Format an IPv6 address according to RFC 5952.
    // https://tools.ietf.org/html/rfc5952

    var ipv6_u16s: @Vector(8, u16) = @as(*align(@alignOf(netparser.network.IPv6Address)) const [8]u16, @ptrCast(&ipv6_addr[0])).*;
    ipv6_u16s = std.mem.nativeToBig(@Vector(8, u16), ipv6_u16s);

    // Find the longest sequence of zeros.
    var longest_zero_start: usize = 0;
    var longest_zero_length: usize = 0;
    var current_zero_start: usize = 0;
    var current_zero_length: usize = 0;
    for (0..8) |index| {
        const field = ipv6_u16s[index];
        if (field == 0) {
            if (current_zero_length == 0) {
                current_zero_start = index;
            }
            current_zero_length += 1;
        } else {
            if (current_zero_length > longest_zero_length) {
                longest_zero_start = current_zero_start;
                longest_zero_length = current_zero_length;
            }
            current_zero_length = 0;
        }
    }

    // Print the address.
    for (0..8) |index| {
        const field = ipv6_u16s[index];
        if (index == longest_zero_start and longest_zero_length > 1) {
            try std.fmt.format(writer, ":", .{});
        } else if (index > longest_zero_start and index < longest_zero_start + longest_zero_length) {
            // Skip the zeros.
        } else {
            try std.fmt.format(writer, "{s}{x}", .{ if (index != 0) ":" else "", field });
        }
    }
}

fn get_source_port_from_link_layer_payload(link_layer_payload: *const netparser.link.LinkLayerPayload) !?u16 {
    switch (link_layer_payload.*) {
        .Ethernet => |eth_layer| {
            switch (eth_layer.payload) {
                .IPv4 => |ipv4| {
                    return get_source_port_from_ipv4_6(&ipv4.payload);
                },
                .IPv6 => |ipv6| {
                    return get_source_port_from_ipv4_6(&ipv6.payload);
                },
                .ARP => {
                    return null;
                },
                .unknown => {
                    return null;
                },
            }
        },
        .Null => |null_layer| {
            switch (null_layer.payload) {
                .IPv4 => |ipv4| {
                    return get_source_port_from_ipv4_6(&ipv4.payload);
                },
                .IPv6 => |ipv6| {
                    return get_source_port_from_ipv4_6(&ipv6.payload);
                },
            }
        },
    }
}

fn get_source_port_from_ipv4_6(ipv4_6_packet: *const netparser.network.IPv4Payload) !?u16 {
    switch (ipv4_6_packet.*) {
        .IPv6_HopByHopOpt, .ICMP, .IGMP, .IPv6_ICMP, .IPv6_Route, .FragmentedPacket => {
            return null;
        },
        .TCP => |tcp| {
            return tcp.source_port;
        },
        .UDP => |udp| {
            return udp.source_port;
        },
    }
}

fn get_dest_port_from_link_layer_payload(link_layer_payload: *const netparser.link.LinkLayerPayload) !?u16 {
    switch (link_layer_payload.*) {
        .Ethernet => |eth_layer| {
            switch (eth_layer.payload) {
                .IPv4 => |ipv4| {
                    return get_dest_port_from_ipv4_6(&ipv4.payload);
                },
                .IPv6 => |ipv6| {
                    return get_dest_port_from_ipv4_6(&ipv6.payload);
                },
                .ARP => {
                    return null;
                },
                .unknown => {
                    return null;
                },
            }
        },
        .Null => |null_layer| {
            switch (null_layer.payload) {
                .IPv4 => |ipv4| {
                    return get_dest_port_from_ipv4_6(&ipv4.payload);
                },
                .IPv6 => |ipv6| {
                    return get_dest_port_from_ipv4_6(&ipv6.payload);
                },
            }
        },
    }
}

fn get_dest_port_from_ipv4_6(ipv4_6_packet: *const netparser.network.IPv4Payload) !?u16 {
    switch (ipv4_6_packet.*) {
        .IPv6_HopByHopOpt, .ICMP, .IGMP, .IPv6_ICMP, .IPv6_Route, .FragmentedPacket => {
            return null;
        },
        .TCP => |tcp| {
            return tcp.destination_port;
        },
        .UDP => |udp| {
            return udp.destination_port;
        },
    }
}
