# Appsealing Research and Reverse Engineering

This document provides an analysis of the Appsealing app protection system, including its research and reverse engineering. It outlines the system's detection measures, explores its code, and discusses some of its strengths and weaknesses. The document also provides insights into the system's Java and Entry side, string decryption approach, and its potentially questionable detections.
This is all for educational purposes only and I don't mean to cause any security issues for existing apps.

## General Research & Information

### AndroidManifest.xml

Let's get straight to it. One thing found in the manifest is a list of blocked apps on the device. Below are just a few of them but should give a general idea. Personally, I don’t think that this is a necessarily good idea to do as it contributes to the concept of “security through obscurity”. A lot of the listed apps such as a popular file manager named MT Manager are blocked for no obvious reason. My assumption is that it’s blocked due to MT Manager having features like APK-Signature bypassing however, that’s not a valid reason the completely block it.

This approach of checking if an app is installed is definitely smart as it does not require the QUERY_ALL__PACKAGES permission which seems to be blocked by the google play store.

```xml
<package android:name="app.greyshirts.sslcapture"/>
<package android:name="app.greyshirts.sslcapturess"/>
<package android:name="apps.zhasik007.hack"/>
<package android:name="be.uhasselt.privacypolice"/>
```

### Assets

The assets folder also contains some interesting things such as the encrypted/sealed dexes. Those are decrypted and loaded from the native library using the InMemoryDexClassLoader. I will get to how this works later.

## Java

Looking at the java code in JADX we can find a few interesting things such as analytics that send information about the device to their server. The list looks as follows:

```xml
- Country
- Package Name
- App Version
- Android Version
- Model
- Manufacturer
- Device ID
- SDK Version
- Hardware
- CPU Architecture
- Kernel Version
- Display
- Brand
```

Personally, I consider that completely unnecessary. An app protection solution does NOT need to have any of these things. It’s questionable what is done with this information as it surely is not important to detect modifications, especially not server sided. 

Since I’m working with a Unity game here it’s also worth going over some over the custom Unity loader they use. Since libraries such as libil2cpp seem to be partly encrypted, it obviously needs to load them itself instead of using the original unity code.

Further look at the Java side uncovers a class named AppSealingZygote which implements ZygotePreload. This class seems to be responsible for loading the actual native library libcovault-appsec. This class seems really funny as the ZygotePreload trick has it’s origin in an open source root detector which I’m sure they implemented but more on that later. This trick however has been patched long time ago and does not apply to any new release of Magisk. 

**Off Topic: Java server connection:** The Java code implements a class named AwsSqsSender which from my understanding is responsible for sending the previously named Analytics to the server. The URL is encrypted in a method named getSqsURL in the class AppSealingReport. I’ve gone ahead and decrypted this string and the URL is: “sqs.ap-northeast-1.amazonaws.com/664144478517/report_queue_svc”

The last report is saved to the following location and then uploaded to the sever: “/data/user/0/com.package.name/.sealing_reports/com.package.name” This file also contains a more detailed report of what was detected, which is not even encrypted. It’s stored in plain text. I would have definitely expected something better.

Overall the Java code isn’t protected at all so have a look at if yourself

## Native

Let’s have some fun reversing native code. The native code is a lot worse than I have expected from “The #1 App shielding solution”.

### First look

At first, the native library looks really easy to reverse engineer as it seems like the developers didn’t bother to encrypt a lot of the strings. Funnily enough, a lot of the syscalls seem to use call hide.

A further look at the library shows that it’s partly encrypted similar to libil2cpp however, for analytics, this is not an issue as we can simply dump it from memory and have the full code.

### Entry

In this case, the library entry function is hidden, but not really difficult to find with the “printBuildVer” function

```cpp
__int64 library_entry()
{
  // local variables are not important

  load_syscalls();
  v0 = dword_1BC000;
  if ( dword_1BC000 ) // jni error
  {
    v0 = 65540; // jni success
  }
  else
  {
    printBuildVer();
    
    // function pointers to unknown functions
    qword_1BC008 = off_168D68;
    qword_1BC010 = off_168BD8;
    qword_1BC018 = off_168920;
    qword_1BC020 = off_168C80;
    qword_1BC028 = off_168988;
    qword_1BC030 = nullsub_6;
    dword_1BC038 -= 0x10000;
  
    scan_maps_for_name("libcovault-appsec.so");

    char v19[32];
    load_str(0x20uLL, v19); // /proc/
    sprintf(proc_pid_path, v19, getpid()); // /proc/pid/
    
    if ( !*off_1683A8 )
    {
	    // more hide call logic, not important
      v10 = operator new(8uLL);
      *off_1683A8 = v10;
      *v10 = qword_1BC008 ^ 0xB0C791;
      *off_168B90[0] = 1LL;
      *off_168828[0] = 2LL;
      *off_168250 = 3LL;
      if ( !*off_168DE0 )
        *off_168DE0 = operator new(8uLL);
      **off_168DE0 = qword_1BC010 ^ 0x3081E2;
      if ( !*off_168FE0[0] )
        *off_168FE0[0] = operator new(8uLL);
      **off_168FE0[0] = qword_1BC018 ^ 0xDF087D;
      if ( !*off_168810[0] )
        *off_168810[0] = operator new(8uLL);
      **off_168810[0] = qword_1BC020 ^ 0xED9A3F;
      if ( !*off_168E10 )
        *off_168E10 = operator new(8uLL);
      v3 = *off_168E10;
      v4 = qword_1BC028;
      **off_168E10 = qword_1BC028 ^ 0xED9A3F;
    }
    sub_2C3F4(off_164F38, v3, v4, v5, v6, v7, v8, v9);
    sub_4A72C(off_164F40, v11, v12, v13, v14, v15, v16, v17);
  }
  result = v0;
  if ( v20 != *off_168978 )
    return sub_16640(); // unknown hide call
  return result;
}
```

The code is a bit simplified and does not represent the original code from IDA. I’m not sure if some things broke from the dumping but without dumping it the code isn’t complete.

### Hide Calls

The Protector utilises quite a lot of imports from libc. Some are just directly imported, some are used through a hide call mechanism. It works like the following:

1. Initialise a global variable with the address. (signal_0 has manually renamed)
    
    ```cpp
    .data:0000000000168410 signal_0 DCQ signal; DATA XREF: load_syscalls+13C↑o
    ```
    
2. Assign the address to a function pointer, also a global variable
    
    ```cpp
    if ( !signal_syscall )
        signal_syscall = operator new(8uLL);
      v4 = signal_syscall;
      *v4 = operator new(8uLL);
      **signal_syscall = qword_185D98 ^ signal_0;
    ```
    
    Here, the variable “qword_185D98” seems to be a random number. I’m sure this is an issue caused by dumping however it doesn’t affect anything here.
    
3. This pointer is again assigned to another function pointer, here (signal_1).
4. Call the “hidden” function
    
    ```cpp
    ((***signal_1 ^ *off_1685C8))(14LL, 0LL);
    ```
    

Simplified, the code looks like this:

```cpp
void *signal_0 = (void *)signal;

if (signal_syscall == nullptr) {
  signal_syscall = signal_0;
}

signal_1 = signal_syscall;
```

### Wrapper Functions

Quite a lot of functions like fopen have wrapper function to make coding easier I assume. Nothing really special here, just a side note.

```cpp
FILE *__fastcall custom_fopen(const char *a1, const char *a2)
{
  return fopen_interal(a1, a2);
}
```

### Dex Decryption

Just dump them from memory and replace it with the one in the apk.

### Exit Routine

When something is detected, a message box with a countdown will be shown. This message box is shown in the class “AppSealingAlertDialog” with the method “showAlertDialog”. When the countdown runs out, the app is killed using another method in “AppSealingAlertDialog” named “killMyProcess”. 

The message box can easily be bypassed by using xposed hooks or by patching the java code to make the method return before running any code. More on that later.

For the native part, it’s simply a combination of “kill”, “signal” and “alarm”. Once you patch/hook these, the app won’t crash anymore.

## Detections

Let’s go over some detections found in the native library. I was quite lazy here and didn’t really focus on finding the exact things checked for. Find these yourself.

### Rooting

To be honest, during the time of reversing, I did not come across a single Root detection on my rooted device using KernelSU. Testing KitsuneMagisk also seems to not be detected, showing how basic their root check actually is. However, this may just be on my device so let’s back this up with some analytics:

I have used ltrace and strace here to do some syscall tracing as I didn’t want to bother spending too much time on it. Even with this, I really didn’t find a lot which supports my point of the root check being really weak.

```cpp
**fopen** -> /proc/self/mountstats
**fopen** -> /proc/self/environ // maybe check environment variables for su
```

### Payment Bypass Detection

This is a bad one, it’s just a check if hosts file is modified. It should be a root detection, not a “payment bypass”.

```cpp
**fopen** -> /system/etc/hosts
**open** -> /system/etc/hosts
```

You may be wondering how I know that this is related to the payment bypass detection, and to that I want to remind you that the detection is stored in **plain text** in the report file.

### Debugger Detection

Very simple, only done by checking /proc/pid/status for TracerPid. Debuggers/Tracers such as ltrace are not even affected by this.

### Frida Detection

Frida Detection is done through “/proc/self/task/tid/status” and checking if it’s a frida task.

There is probably more here but I didn’t bother checking.

### Others

Detections such as USB Debugging, Developer Options or App detection should be self explanatory. I don't think these checks have ANY real use for security.

### Questionable Detections

There it a whole list of them so let’s get started

1. **Keylogger detection**: Straight up a lie, there is no detection except searching for “known” apps that may contain keyloggers. This is NOT protection as renaming the package name of an app takes less than 5 minutes.
2. **Macro tools block**: Again, only applies to the predefined list of apps. Renaming the package name fixes it.
3. **Block Screen Mirroring & Capture**: I don’t see how that is a security issue. Screen recording tools, especially in games are important for the games growth. I do understand this this may be useful for banking apps however I would not use this tool if I wanted to protect a banking app.
4. **Blocking USB Debugging**: USB debugging is used by app developers. If you block USB Debugging, at least also block terminal emulator apps as they allow for the same exact things as USB debugging does (none).
5. **Block memory manipulation**: Weirdly enough, the Linux system call “proc_vm_readv” & “proc_vm_writev” are not detected by appsealing.
6. **Game Guardian:** I’m sorry to bring this up to you, however, detecting Game Guardian by the package name “catch_me_if_you_can” maybe worked 5 years ago but not anymore. However, here I have to actually give you the credit for blocking it’s overlay on Android 12 and above.

I don’t intent to hate on AppSealing here but selling something like that calling it “#1 App protection service” with “20 years of experience” does not seem right to me. Especially considering that a lot of these detections can be found open source on github.

## Bypass

Like I have already mentioned earlier, the protection really isn’t difficult to bypass. However, for the record, let’s go over both ways to remove it.

### 1. Remove the Entire plugin

At first, this seems like a really good idea however, due to the dex encryption we can’t just remove it as huge parts of the dex would be missing. Same goes for the native libraries. From my current analytics, it seems like only the the encryption happens in their native library.

I’ve already gave away a lot of information about this solution so I’m sure you can figure out how the decryption works yourself :)

### 2. Bypass the Dialog and the Exit

Let me repeat what I have mentioned earier: “The message box can easily be bypassed by using xposed hooks or by patching the java code to make the method return before running any code.”.

Let’s do it with the xposed api first:

```java
XposedHelpers.findAndHookMethod("com.inka.appsealing.AppSealingAlertDialog", cl, "showAlertDialog", Context.class, int.class, Object.class, boolean.class, new XC_MethodHook() {
  @Override
  protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
		param.setResult(null);
	}
});
XposedHelpers.findAndHookMethod("com.inka.appsealing.AppSealingAlertDialog", cl, "killMyProcess", int.class, new XC_MethodHook() {
  @Override
  protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    param.setResult(null);
  }
});
```

Now with patching the Java code:

```java
public static void showAlertDialog(Context context, int i, Object obj, boolean z) {
	Log.i("Bypass", "showAlertDialog");
}

private void killMyProcess(final int i) {
	Log.i("Bypass", "killMyProcess");
}
```

I’ll leave it up to you to figure out how to achieve this with smali patching :)

**Native Bypass**: For the native part, it’s simply a combination of “kill”, “signal” and “alarm”. So let’s simply do a hook and it won’t kill the app anymore.

```cpp
HOOK(unsigned int, alarm_hook, unsigned int seconds) {
    return 0;
}

HOOK(int, kill_hook, int pid, int sig) {
    return 0;
}

DobbyHook((void *) alarm, (void *) alarm_hook, (void **)&orig_alarm_hook);
DobbyHook((void *) kill, (void *) kill_hook, (void **) &orig_kill_hook);
```

That was easy, wasn’t it? We didn’t even have to dig into the detection code to bypass it.

## Conclusion

In summary, the AppSealing solution its strengths and weaknesses, however, personally I’d say that there are a lot more weaknesses than strengths. It is clear that while the system has implemented some smart strategies to prevent removal through encrypting other native libraries. However like already mentioned, the weaknesses are bigger than the strengths, for instance, the lack of string encryption and the nature of weak detection methods. Also questionable practice of sending extensive device information to their servers don’t make this solution more secure. 

I also provide a potential bypass methods for the security measures implemented, the bypass is purely for educational purposes only and is not meant to cause any trouble with apps. I encourage the developers to take following actions:

- Proper native library protections through ObfuscatorLLVM, don’t just obfuscate parts.
- String Encryption
- Java sided Obfuscation
- Overall improvement of detections, especially against external threads such as xposed and frida
- A more complicated exit routine through multiple methods (kill, exit, syscalls, etc.)
- Implement real detections instead of relying on app detections for apps that might even be unrelated to the security

While the Appsealing system is branded as a top-tier app shielding solution, this research suggests that huge improvements can be made to enhance it’s security.
I have already contacted the developers about these issues but until this day have not received any response which provides even more proof how much the developers actually care about security.

## Finally

If you have any questions you can contact me via email or discord

Discord: @arandomperson9815

Email: [randomperson076@protonmail.com](mailto:randomperson076@protonmail.com)
