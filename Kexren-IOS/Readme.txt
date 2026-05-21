Kexren-IOS

iOS kernel research tool for educational use on personally owned devices. No game modifications or cheats provided. Not affiliated with Apple, Activision, or Timi Studio. Security research only.

Current Capabilities

| Feature | Status |
|---------|--------|
| Get CODM PID | ✅ Working |
| Full kernel-level game access | ✅ Working |
| Auto-execute hacks | ✅ Working (if implemented) |
| External overlay / mod menu | ❌ Broken |

How It Works

1. Attaches to game process via PID
2. Gains kernel-level read/write access
3. Can auto-execute hacks on attachment
4. Overlay system is currently non-functional

If You Want to Fix the Overlay

The overlay is broken, preventing external CODM hacks from appearing. If you can fix it, the exploit will support:

- External CODM mod menu
- Runtime hack toggling
- Visual overlay interface

Build Requirements

- iOS 17.0 - 18.7.1 or 26.0 - 26.0.1
- Not for M5/A19 devices (MIE limitation)
- M-series devices: Set `t1sz_boot` to `0x11` in Lara settings

Credits

Darklunaios – Source code, exploit research, PID grabbing & kernel access  
Contact: [t.me/Darklunaios](https://t.me/Darklunaios)

Lara – Original exploit integration  
GitHub: [https://github.com/rooootdev/lara](https://github.com/rooootdev/lara)

 Lara Credits

- opa334 – Kernel exploit POC, ChOma, XPF
- AppInstaller iOS – Offsets help
- AlfieCG – libgrabkernel2
- rooootdev – Lara owner

 Legal

For educational and security research only. Use only on devices you own.