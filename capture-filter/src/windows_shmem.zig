const std = @import("std");
const windows = std.os.windows;
const kernel32 = std.os.windows.kernel32;

pub const FILE_MAP_WRITE = windows.SECTION_MAP_WRITE;
pub const FILE_MAP_READ = windows.SECTION_MAP_READ;
pub const FILE_MAP_ALL_ACCESS = windows.SECTION_ALL_ACCESS;

pub const FILE_MAP_COPY = 0x1;
pub const FILE_MAP_RESERVE = 0x80000000;
pub const FILE_MAP_TARGETS_INVALID = 0x40000000;
pub const FILE_MAP_LARGE_PAGES = 0x20000000;

pub extern "kernel32" fn CreateFileMappingA(
    hFile: windows.HANDLE,
    lpFileMappingAttributes: ?*windows.SECURITY_ATTRIBUTES,
    flProtect: windows.DWORD,
    dwMaximumSizeHigh: windows.DWORD,
    dwMaximumSizeLow: windows.DWORD,
    lpName: ?windows.LPCSTR,
) callconv(windows.WINAPI) ?windows.HANDLE;

pub extern "kernel32" fn MapViewOfFileEx(
    hFileMappingObject: windows.HANDLE,
    dwDesiredAccess: windows.DWORD,
    dwFileOffsetHigh: windows.DWORD,
    dwFileOffsetLow: windows.DWORD,
    dwNumberOfBytesToMap: windows.SIZE_T,
    lpBaseAddress: ?*anyopaque,
) callconv(windows.WINAPI) ?*anyopaque;

pub extern "kernel32" fn UnmapViewOfFile(
    lpBaseAddress: *anyopaque,
) callconv(windows.WINAPI) windows.BOOL;
