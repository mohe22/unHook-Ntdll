


# Unhooking `ntdll.dll` – Windows EDR Evasion

This project is a simple C++ utility that restores the `.text` section of `ntdll.dll` in memory by copying a clean version from disk. This is often used in security research or red teaming to **bypass EDR (Endpoint Detection and Response)** hooks injected in user-mode.

---

## 🛠 Overview

Modern EDR solutions often hook system calls in `ntdll.dll` by modifying its `.text` section (where syscalls are implemented). These hooks let EDR intercept and inspect malicious behavior.

This tool:

1. Loads a clean copy of `ntdll.dll` from disk (`C:\Windows\System32\ntdll.dll`)
2. Locates the `.text` section of the clean and in-memory versions
3. Validates that both sections match in size
4. Uses `VirtualProtect` to change the memory protection
5. Overwrites the in-memory `.text` section with the clean version
6. Flushes the instruction cache to apply changes

---

## 📦 Files

- `Unhooker.cpp`: Main code logic.
- `Unhooker.h`: Header file (assumed to declare functions).
- `README.md`: This file.

---

## ✅ How to Run

### 🧱 Requirements
- Windows OS
- Visual Studio or g++
- Admin privileges (recommended)

### 🧪 Steps

1. **Compile:**
   If using Visual Studio:
   - Create a new project and add `Unhooker.cpp` and `Unhooker.h`
   - Build the solution

   If using g++ with MinGW:
   ```bash
   g++ -o Unhooker.exe Unhooker.cpp
    ````

2. **Run:**

   ```bash
   Unhooker.exe
   ```

3. **Expected Output:**

   ```
   [+] Unhooking ntdll.dll...
   [+] Memory .text section: 0x<address> | Size: 0x<hex>
   [+] Disk .text section: 0x<address> | Size: 0x<hex>
   [+] Memory protection changed to RWX
   [+] .text section restored
   [+] Protection restored
   [+] Unhooking successful!

---

## 📖 Full Explanation

A detailed explanation of how this code works, including background on hooks, PE headers, section parsing, and syscall restoration is available on my blog:

🔗 **Read it here:**
[https://portfolio-three-alpha-27.vercel.app/Blogs/unhooking-ntdll](https://portfolio-three-alpha-27.vercel.app/Blogs/unhooking-ntdll)

