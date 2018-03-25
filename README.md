## de4dot CEx
A de4dot fork with full support for vanilla ConfuserEx

## Features
* Supports x86 (native) mode
* Supports normal mode
* Decrypts and inlines constants
* Decrypts resources
* Fixes control flow
* Fixes proxy calls
* Deobfuscated assemblies are runnable

## Notes
* You have to unpack the obfuscated assembly **before** running this deobfuscator. The easiest way is to dump the module/s just after the methods have been decrypted.
* This deobfuscator uses method invocation for constant decryption, therefore you always **risk** running malware if it's present in the obfuscated assembly. Be cautious and use a VM/Sandboxie!

### [Original README](README-orig.md)
---

## Samples

### Before (obfuscated symbols shortened):
```csharp
ublic byte[] ShiftAddress(uint address)
{
	byte[] array = new byte[4];
	for (;;)
	{
		IL_07:
		int num = -2174478396;
		for (;;)
		{
			uint num2;
			switch ((num2 = (uint)<Module>.a(num)) % 7u)
			{
			case 0u:
				goto IL_07;
			case 1u:
			{
				int num3 = 0;
				num = (int)(num2 * 81144519u ^ 2359132411u);
				continue;
			}
			case 2u:
				num = (int)(num2 * 2975731004u ^ 34171348176);
				continue;
			case 3u:
			{
				int num3;
				num3++;
				num = (int)(num2 * 2174567110u ^ 244457623u);
				continue;
			}
			case 5u:
			{
				int num3;
				num = ((num3 >= 4) ? 631278122 : 1299552879);
				continue;
			}
			case 6u:
			{
				int num3;
				array[num3] = (byte)(address >> num3 * 8 & 255u);
				num = 556578930;
				continue;
			}
			}
			return array;
		}
	}
	return array;
}
```

### After:
```csharp
public byte[] ShiftAddress(uint address)
{
	byte[] array = new byte[4];
	for (int i = 0; i < 4; i++)
	{
		array[i] = (byte)(address >> i * 8 & 255u);
	}
	return array;
}
```

### Before (obfuscated symbols shortened):
```csharp
public bool WriteBytes(uint address, List<byte> buffer)
{
	byte[] array = buffer.ToArray();
	IntPtr intPtr;
	uint num = Memory.a(this.Handle, b((long)((ulong)address)), array, (uint)array.Length, out intPtr);
	for (;;)
	{
		IL_25:
		int num2 = 482469350;
		for (;;)
		{
			uint num3;
			switch ((num3 = (uint)<Module>.c(num2)) % 5u)
			{
			case 0u:
				this.d.Account.Log.WriteLine(<Module>.e<string>(3167610260u));
				num2 = (int)(num3 * 3588940066u ^ 1074051690u);
				continue;
			case 2u:
				return false;
			case 3u:
				goto IL_25;
			case 4u:
				num2 = (int)(((num != 0u) ? 4496537787u : 434512514u) ^ num3 * 589449693u);
				continue;
			}
			goto Block_1;
		}
	}
	Block_1:
	return true;
}
```

### After:
```csharp
public bool WriteBytes(uint address, List<byte> buffer)
{
	byte[] array = buffer.ToArray();
	IntPtr intPtr;
	if (Memory.WriteProcessMemory(this.Handle, (IntPtr)((long)((ulong)address)), array, (uint)array.Length, out intPtr) == 0u)
	{
		this.Owner.Console.Log.WriteLine("WriteBytes failed: WriteProcessMemory failed");
		return false;
	}
	return true;
}
```
