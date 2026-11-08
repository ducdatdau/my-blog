---
title: "Phân tích firmware IoT với Binwalk và Ghidra"
date: 2026-11-08
categories: [Research]
tags: [iot, firmware, reverse-engineering]
---

## Giới thiệu

Bài viết này trình bày quy trình phân tích firmware của một thiết bị IoT phổ biến, từ việc extract firmware đến tìm lỗ hổng bảo mật.

## Công cụ sử dụng

| Tool | Mục đích |
|------|----------|
| Binwalk | Extract firmware |
| Ghidra | Reverse engineering |
| QEMU | Emulate firmware |
| Wireshark | Phân tích traffic |

## Bước 1: Extract firmware

```bash
binwalk -e firmware.bin
```

```
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header
64            0x40            LZMA compressed data
1048576       0x100000        Squashfs filesystem
```

## Bước 2: Phân tích filesystem

Sau khi extract, ta có cấu trúc filesystem Linux chuẩn:

```
squashfs-root/
├── bin/
├── etc/
├── lib/
├── usr/
└── www/
```

Kiểm tra file cấu hình để tìm hardcoded credentials:

```bash
grep -r "password" squashfs-root/etc/
```

## Kết luận

Qua phân tích, phát hiện 2 lỗ hổng chính:
1. **Hardcoded credentials** trong `/etc/config/admin.conf`
2. **Command injection** trong web interface tại endpoint `/api/diagnostic`

Đã report cho vendor theo quy trình responsible disclosure.
