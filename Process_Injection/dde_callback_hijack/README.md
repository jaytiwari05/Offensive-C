# DDE Callback Hijacking

`DDE Callback Hijacking` is a process injection technique that abuses the callback pointer (`pfnCallback`) stored inside Windows' DDE subsystem. By replacing this callback with shellcode and triggering a DDE transaction, the target process executes the shellcode on its existing GUI thread without creating a new thread.

This is a Proof of Concept for this technique, i assume you should make changes and then use it because this POC just Pop a MessageBox

---

### Compling command

Windows Developer Command Prompt
```powershell
cl DDE-Callback-Hijack.c /link user32.lib
```

Linux
```bash
x86_64-w64-mingw32-gcc.exe DDE-Callback-Hijack.c -o DDE-Callback-Hijack.exe -luser32
```

---

### References
https://ring0din.github.io/posts/dde-callback-hijacking/

https://modexp.wordpress.com/2019/08/09/windows-process-injection-breaking-badder/

https://learn.microsoft.com/en-us/windows/win32/dataxchg/about-dynamic-data-exchange