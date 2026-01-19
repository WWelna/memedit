// Copyright (C) 2026 William Welna (wwelna@occultusterra.com)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following condition.

// * The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.

// In addition, the following restrictions apply:

// * The software, either in source or compiled binary form, with or without any
//   modification, may not be used with or incorporated into any other software
//   that used an Artificial Intelligence (AI) model and/or Large Language Model
//   (LLM) to generate any portion of that other software's source code, binaries,
//   or artwork.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

const std = @import("std");
const clap = @import("clap");

var gpa = std.heap.DebugAllocator(.{}){};
const gpa_allocator = gpa.allocator();

var stdout_buffer: [1024]u8 = undefined;
var stdout_writer_wrapper = std.fs.File.stdout().writer(&stdout_buffer);
const stdout: *std.io.Writer = &stdout_writer_wrapper.interface;

const MapEntry = struct {
    start_addr: usize,
    end_addr: usize,
    readable: bool,
    writable: bool,
    executable: bool,
    is_private: bool,
    offset: usize,
    dev_major: u8,
    dev_minor: u8,
    inode: usize,
    path: []const u8,
    chunk: ?[]u8,
};

const Error = error{
    readMemError,
    ptraceAttach,
    ptraceDetach,
    ptracePeek,
};

// This use to work in a time long ago but doesn't anymore (needs CAP_SYS_PTRACE), etc. so PTRACE it is
// pub fn _broken_grabChunk(pid: std.os.linux.pid_t, start_addr: usize, end_addr: usize) ![]u8 {
//     var open_buffer: [256]u8 = undefined;
//     var read_buffer: [1024]u8 = undefined;
//     const size: usize = end_addr - start_addr;
//     var mem = try std.fs.cwd().openFile(try std.fmt.bufPrint(&open_buffer, "/proc/{any}/mem", .{pid}), .{ .mode = .read_only });
//     defer mem.close();
//     var frb = mem.reader(&read_buffer);
//     var reader = &frb.interface;

//     try mem.seekTo(start_addr);
//     const ret = try gpa_allocator.alloc(u8, size);
//     errdefer gpa_allocator.free(ret);
//     try reader.readSliceAll(ret);

//     std.debug.print("[{d}] Scanning Memory Block {x} of size {d} via /proc/\n", .{ pid, start_addr, size });

//     if (ret.len != size) return Error.readMemError else return ret;
// }

pub fn grabChunk(pid: std.os.linux.pid_t, start_addr: usize, end_addr: usize) ![]u8 {
    const size: usize = end_addr - start_addr;
    const ret = try gpa_allocator.alloc(u8, size);
    errdefer gpa_allocator.free(ret);

    try stdout.print("[{d}] Scanning Memory Block {x} of size {d}\n", .{ pid, start_addr, size });
    try stdout.flush();

    var call_count = size / @sizeOf(usize);
    var addr = start_addr;

    while (call_count > 0) : (call_count -= 1) {
        const word = try peek(pid, addr);
        const copy_len = @min(@sizeOf(usize), end_addr - addr);
        const offset = (addr - start_addr);

        @memcpy(ret[offset..(copy_len + offset)], std.mem.asBytes(&word)[0..copy_len]);

        addr += @sizeOf(usize);
    }

    return ret;
}

pub fn openmap(pid: std.os.linux.pid_t) !std.ArrayList(MapEntry) {
    var open_buffer: [256]u8 = undefined;
    var read_buffer: [1024]u8 = undefined;
    var ret: std.ArrayList(MapEntry) = .empty;
    errdefer ret.deinit(gpa_allocator);
    var map = try std.fs.cwd().openFile(try std.fmt.bufPrint(&open_buffer, "/proc/{any}/maps", .{pid}), .{ .mode = .read_only });
    defer map.close();
    var frb = map.reader(&read_buffer);
    var reader = &frb.interface;

    while (reader.takeDelimiterInclusive('\n')) |line| {
        var it = std.mem.splitAny(u8, line, " ");

        const addr_range_str = it.next().?;
        const perms_str = it.next().?;
        const offset_str = it.next().?;
        const dev_str = it.next().?;
        const inode_str = it.next().?;
        const path = it.rest();
        const path_dup = try gpa_allocator.dupe(u8, path);
        errdefer gpa_allocator.free(path_dup);

        var addr_it = std.mem.splitAny(u8, addr_range_str, "-");
        const start_addr = try std.fmt.parseInt(usize, addr_it.next().?, 16);
        const end_addr = try std.fmt.parseInt(usize, addr_it.next().?, 16);

        var dev_it = std.mem.splitAny(u8, dev_str, ":");

        try ret.append(gpa_allocator, .{
            .start_addr = start_addr,
            .end_addr = end_addr,
            .readable = if (perms_str[0] == 'r') true else false,
            .writable = if (perms_str[1] == 'w') true else false,
            .executable = if (perms_str[2] == 'x') true else false,
            .is_private = if (perms_str[3] == 'p') true else false,
            .offset = try std.fmt.parseInt(usize, offset_str, 16),
            .dev_major = @truncate(try std.fmt.parseInt(usize, dev_it.next().?, 16)),
            .dev_minor = @truncate(try std.fmt.parseInt(usize, dev_it.next().?, 16)),
            .inode = try std.fmt.parseInt(usize, inode_str, 10),
            .path = path_dup,
            .chunk = if (perms_str[1] == 'w') try grabChunk(pid, start_addr, end_addr) else null,
        });

        //break;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => {
            return err;
        },
    }

    return ret;
}

pub fn closemap(map: *std.ArrayList(MapEntry)) void {
    for (map.items) |e| {
        gpa_allocator.free(e.path);
        if (e.chunk) |v| gpa_allocator.free(v);
    }
    map.deinit(gpa_allocator);
}

pub fn attach(pid: std.os.linux.pid_t) !void {
    const ret = std.os.linux.ptrace(std.os.linux.PTRACE.ATTACH, pid, 0, 0, 0);
    if (ret != 0) {
        std.debug.print("[{d}] PTRACE.ATTACH Error: {d}\n", .{ pid, ret });
        return Error.ptraceAttach;
    }
    var status: u32 = undefined;
    _ = std.os.linux.waitpid(pid, &status, 0);
}

pub fn detach(pid: std.os.linux.pid_t) !void {
    const ret = std.os.linux.ptrace(std.os.linux.PTRACE.DETACH, pid, 0, 0, 0);
    if (ret != 0) {
        std.debug.print("[{d}] PTRACE.DETACH Error: {d}\n", .{ pid, ret });
        return Error.ptraceDetach;
    }
}

// pub fn cont(pid: std.os.linux.pid_t) !void {
//     const ret = std.os.linux.ptrace(std.os.linux.PTRACE.CONT, pid, 0, 0, 0);
//     if (ret != 0) return Error.ptraceDetach;
// }

pub fn peek(pid: std.os.linux.pid_t, addr: u64) !usize {
    const word = std.os.linux.ptrace(std.os.linux.PTRACE.PEEKDATA, pid, addr, 0, 0);
    return word;
}

pub fn dopid(pid: std.os.linux.pid_t) !void {
    try attach(pid);
    var map = try openmap(pid);
    defer closemap(&map);
    try detach(pid);
}

pub fn main() !void {
    defer _ = gpa.deinit();

    // TODO: Make this actually work
    try dopid(3140335);

    try stdout.flush();
}
