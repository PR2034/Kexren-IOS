# Kexren-IOS

**iOS Kernel Process Introspection Tool – Educational Research Only**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-iOS-lightgrey.svg)]()

---

## 📖 About

Kexren-IOS is an **educational research tool** designed for security researchers and reverse engineers to study iOS kernel-level process interaction on devices they personally own.

**This tool does not:**
- Include any game cheats, mod menus, or pre-built hacks
- Bypass any game's anti-cheat systems
- Modify copyrighted game code or assets
- Provide any functionality to gain unfair advantage in online games

---

## ⚙️ Technical Capabilities (Research Context)

| Capability | Status | Description |
|------------|--------|-------------|
| Process identification | ✅ | Locates running processes by name |
| Memory introspection | ✅ | Read-only kernel-level process access |
| Automation hooks | ✅ | User-implemented execution triggers |
| Graphical interface | ⚠️ | Currently non-functional (under research) |

---

## 📱 Compatibility

| iOS Version | Research Status |
|-------------|-----------------|
| iOS 16.x | Not compatible |
| iOS 17.0 – 18.7.1 | Compatible |
| iOS 18.7.2+ | Not compatible |
| iOS 26.0 – 26.0.1 | Compatible |
| iOS 26.1+ | Not compatible |

**Hardware limitations:** Not compatible with M5 or A19 (Pro) devices due to hardware security architecture.

---

## 🔧 Building from Source

```bash
git clone https://github.com/YOUR_USERNAME/Kexren-IOS.git
cd Kexren-IOS
# Open Xcode project and build for your target device
