# CS2 Internal/External Hybrid Cheat

An advanced Counter-Strike 2 hybrid cheat designed with stealth, stability, and adaptability in mind. This project blends internal and external cheat methodologies, combining high performance with strong anti-detection techniques.

> ⚠️ **Disclaimer:** This project is for educational purposes only. I do not condone cheating in multiplayer games. Use at your own risk.

---

## ✨ Features

### 🔐 Security & Stealth
- **PE Header Wiping:** Erases PE headers post-injection to prevent memory scanning.
- **Unlink From PEB Lists:** Unlinks the module from the process's loader lists (InLoadOrder, InMemoryOrder, InInitializationOrder).
- **Debug Directory Wipe:** Clears debug information from the module to obscure its presence.
- **Import Table Wipe:** Removes import descriptors after resolving them to avoid static analysis.
- **Spoofed Execution Thread:** Creates a fake thread under the target process to evade thread-based detection.

### 🧠 Auto-Offset Management
- **Offset Auto-Updater:** Uses pattern an external offset dump service to always stay updated with the latest CS2 structures and addresses.

### 🧬 Hybrid Injection Design
- **Internal/External Fusion:**
  - Supports DLL injection into target processes with stealthy memory and thread manipulation.
  - Automatically hijacks a valid handle from the target (e.g., CS2) and duplicates it to prevent permission issues.
  - Cleanly manages thread execution within the spoofed context of the target process.

### 🖼️ Undetectable Overlay
- **Usermode Overlay Rendering:** Utilizes a stealth overlay method that avoids typical detection vectors used by anti-cheats (e.g., no window hooks, layered window obfuscation).

---

## 🛠️ Requirements
- Windows 10/11 x64
- Administrator privileges (for handle and memory operations)
- Visual Studio 2022 (C++17 or higher)

---

## 🧪 Injection Modes

| Mode        | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| Internal    | Injects a DLL directly into the CS2 process and initializes internally.     |
| External    | Executes core logic from a separate process using duplicated spoofed handle. |
| Hybrid      | Uses both internal and external techniques for maximum stealth and control. |

---

## 🚀 Usage

1. **Build** the solution using Visual Studio.
2. **Launch CS2** and leave it running.
3. **Inject DLL or Run EXE** (manual map injection recommended for stealth).
4. The cheat will:
   - Hijack a valid handle.
   - Duplicate and use it for further operations.
   - Launch a spoofed thread in the context of CS2.
   - Render overlay and execute logic.

---

## TODO
- Add Features Lol (rn its barebones, but the offsets that it has rn are enough to make glow esp with.)