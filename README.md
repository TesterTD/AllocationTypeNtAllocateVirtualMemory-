# AllocationTypeNtAllocateVirtualMemory
**Types of allocation in NtAllocateVirtualMemory**

> The analysis is based on the disassembled code of `ntoskrnl.exe` (IDA Pro), WinDbg, and HyperDbg debugging.

## Table of Contents
# EMPTY...

## Function View
```c
NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,   // target process handle
    PVOID    *BaseAddress,     // desired/returned base address
    ULONG_PTR ZeroBits,        // upper address bit limit
    PSIZE_T   RegionSize,      // region size
    ULONG     AllocationType,  // allocation type (MEM_*)
    ULONG     Protect          // page protection (PAGE_*)
);
```

---

## Explanation of each parameter...

### ProcessHandle
Handle of the process in which memory is allocated.

**Special values:**
* `NtCurrentProcess() = (HANDLE)-1` → current process
* Any other handle → foreign process *(requires PROCESS_VM_OPERATION for example)*

### BaseAddress
`[in/out]` Pointer to a variable with an address.

* **Input:**
  * `*BaseAddress = 0` → the kernel will select the address itself
  * `*BaseAddress = 0x400000` → attempt to allocate at a specific address *(aligned down to the 64KB boundary, this is a correct and officially documented approach)*
* **Output:** 
  * `*BaseAddress` = actual allocated address

### ZeroBits
Limits the address range.
* `ZeroBits = 0` → no restrictions
* `ZeroBits = N` → `N` most significant bits of the address must be zero (Maximum address = `(1 << (64 - N)) - 1`)

**Example:**
* `ZeroBits = 32` → address < `0x100000000` (4GB)
* `ZeroBits = 20` → address < `0x100000000000`

### RegionSize
`[in/out]` Size of the allocated region in bytes.

* **Input:** desired size *(rounded up to page boundary = 4KB)*
* **Output:** actual allocated size *(multiple of 4KB)*

> **Note:** `RegionSize = 0` → `STATUS_INVALID_PARAMETER`

---

## Now let's move on and talk about allocation types!

| Flag | Value | Description |
| :--- | :--- | :--- |
| `MEM_COMMIT` | `0x00001000` | Commit physical memory |
| `MEM_RESERVE` | `0x00002000` | Reserve VA without physical memory |
| `MEM_RESET` | `0x00080000` | Page contents are no longer important |
| `MEM_RESET_UNDO` | `0x01000000` | Undo `MEM_RESET` action |
| `MEM_TOP_DOWN` | `0x00100000` | Allocate from highest address |
| `MEM_WRITE_WATCH` | `0x00200000` | Track writes (`GetWriteWatch`) |
| `MEM_PHYSICAL` | `0x00400000` | AWE physical pages |
| `MEM_LARGE_PAGES` | `0x20000000` | Use Large Pages (2MB) |
| `MEM_4MB_PAGES` | `0x80000000` | 4MB pages (x86 only) |
| `MEM_64K_PAGES` | `0x20400000` | 64K pages (`LARGE_PAGES` + `PHYSICAL`) |
| `MEM_DECOMMIT` | `0x00004000` | Only for `NtFreeVirtualMemory` |
| `MEM_RELEASE` | `0x00008000` | Only for `NtFreeVirtualMemory` |

### Information Flags
We also have information flags, for example, the standard `VirtualQuery`/`NtQueryVirtualMemory` handler.

| Flag | Value | Description |
| :--- | :--- | :--- |
| `MEM_FREE` | `0x00010000` | Region is free |
| `MEM_PRIVATE` | `0x00020000` | Private pages of the process |
| `MEM_MAPPED` | `0x00040000` | Mapped section/file |
| `MEM_IMAGE` | `0x01000000` | Mapped PE image |

> **The most delicious thing is that there is one vulnerability in Yara versions 4.3.0 - 4.3.1:** these flags are not visible, hardcoded searches are empty, these are **Placeholder flags!**

| Flag | Value | Description |
| :--- | :--- | :--- |
| `MEM_RESERVE_PLACEHOLDER` | `0x00040000` | Create virtual placeholder |
| `MEM_REPLACE_PLACEHOLDER` | `0x00004000` | Replace placeholder with real memory |
| `MEM_COALESCE_PLACEHOLDERS`| `0x00000001` | Merge adjacent placeholders |
| `MEM_PRESERVE_PLACEHOLDER` | `0x00000002` | Leave placeholder after unmap *(A very awkward and crude approach if you decide to use it for mapping)* |

---

## I will describe some flags in detail, those that I consider necessary.

### MEM_COMMIT (0x00001000)
Based on the fact that it fixes physical memory for pages, in VA addresses `0x10000` → `0x20000`. Physical memory will be reserved.

No, this does not mean that Commit is immediately allocated (Commit ensures that there will be sufficient pagefile/RAM when needed.)

### MEM_RESERVE_PLACEHOLDER (0x00040000)
Creates a virtual placeholder — a reserved region of a special type for managed placement.
Just like `NtAllocateVirtualMemory(MEM_RESERVE | MEM_RESERVE_PLACEHOLDER)`, PLACEHOLDER: `0x10000` → `0x50000`.

Then you can break it down:
```c
NtFreeVirtualMemory(MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER, part)
```
Then replace with actual memory:
```c
NtMapViewOfSectionEx(MEM_REPLACE_PLACEHOLDER)
```

* Ideal for use in memory allocation (SideLoad dll)
* But if we're not talking about mapping for loading manual PE, then work with:
  * Custom allocators with precise address control
  * `VirtualAlloc2` / `MapViewOfFile3`
  * Shared memory with precise layout

---

## Regarding masks for NtAllocateVirtualMemory

```c
// From disassembled NtAllocateVirtualMemory:

// The lower 7 bits are stored separately
LODWORD(v25) = AllocationType & 0x0000007F;

// Bits 7-31 are checked for validity
// If invalid bits are set → STATUS_INVALID_PARAMETER
if ((AllocationType & 0xFFFFFF80) & INVALID_MASK)
    return STATUS_INVALID_PARAMETER;  // 0xC000000D

// Only the most significant bits are passed to MiAllocateVirtualMemoryPrepare
MiAllocateVirtualMemoryPrepare(..., AllocationType & 0xFFFFFF80, ...);
```

---

## About different PROTECT flags 

| Flag | Value | Description |
| :--- | :--- | :--- |
| `PAGE_NOACCESS` | `0x001` | No access (Conditional AV on any access) |
| `PAGE_READONLY` | `0x002` | Read only |
| `PAGE_READWRITE` | `0x004` | Read + Write |
| `PAGE_WRITECOPY` | `0x008` | Copy-on-write (for mapped files) |
| `PAGE_EXECUTE` | `0x010` | Execution only |
| `PAGE_EXECUTE_READ` | `0x020` | Execute + Read |
| `PAGE_EXECUTE_READWRITE` | `0x040` | Execute + Read + Write |
| `PAGE_EXECUTE_WRITECOPY` | `0x080` | Execute + copy-on-write |

### Modifiers for PROTECT
| Modifier | Value | Description |
| :--- | :--- | :--- |
| `PAGE_GUARD` | `0x100` | Trap page (`STATUS_GUARD_PAGE`) |
| `PAGE_NOCACHE` | `0x200` | Non-cacheable memory |
| `PAGE_WRITECOMBINE` | `0x400` | Write-combining (Typically GPU/video memory) |

---

## Now a little chatter about how NtAllocateVirtualMemory is initiated...

A fairly simple definition of call mode:
```c
PreviousMode = KeGetCurrentThread()->PreviousMode;

// PreviousMode == 0  →  KernelMode  (call from kernel)
// PreviousMode == 1  →  UserMode    (call from userspace via syscall)
```

* `NtAllocateVirtualMemory()` → syscall → `PreviousMode = UserMode (1)`, and then the pointers are checked!
* `ZwAllocateVirtualMemory()` → `PreviousMode = KernelMode (0)`, handler skips probe

### Why are probes skipped????

```c
if (PreviousMode) // UserMode
{
    // User/kernel space boundary on x64
    // 0x7FFFFFFF0000 = last valid usermode addresses
    
    const ULONG64 USER_LIMIT = 0x7FFFFFFF0000ULL;
    
    // Check BaseAddress
    ULONG64 safeAddr = (ULONG64)BaseAddress;
    if (safeAddr >= USER_LIMIT)
        safeAddr = USER_LIMIT;  // clamp to safe address
    
    // “Read” pointer — if invalid, will be AV → exception
    *safeAddr = *safeAddr;  // touch operation
    
    // Same for RegionSize
    // ...
}
```

Why is this necessary:
If usermode code passes a pointer to kernel space (for example, `BaseAddress = 0xFFFF800000000000`), then without a probe, the kernel will write the result to its own memory → this is invalid and constitutes a vulnerability.
  
Probe raises an exception before any operations are performed. The exception is intercepted by the SEH block in the system call.

### I really liked the implementation in reading

```c
v13 = *BaseAddress;  // desired address (0 = any)
v14 = *RegionSize;   // desired size

// Save copies for returning the result
v20 = v13;
v21 = v14;
```

### Validation as a nerve-wracking experience LMAO

```c
// Save the lower 7 bits separately
// Bits 0-6: reserved / internal flags
LODWORD(v25) = AllocationType & 0x0000007F;

// Check for invalid bits in range 7-31
// Mask 0xFFFFFF80 covers bits 7..31
// If there are undocumented bits among them — error
if ((SomeConstant & AllocationType & 0xFFFFFF80) != 0)
    return STATUS_INVALID_PARAMETER;  // 0xC000000D = -1073741811
```

---

## MiAllocateVirtualMemoryPrepare...
Internal kernel function. Performs:

1. **Process opening**
   `ObReferenceObjectByHandle(ProcessHandle)` → `EPROCESS`. Stored in `Object[0]`.
2. **Parameter alignment**
   `BaseAddress` → align DOWN to 64KB (`0x10000`).
   `RegionSize` → align UP to 4KB (`0x1000`).
3. **ZeroBits check**
   Ensures that the address complies with the restriction.
4. **Process rights check**
   `PROCESS_VM_OPERATION` handle right.
5. **Memory Partition definition**
   Result → `*((_QWORD *)&v24 + 1)`.
6. **Prepare VAD structure**
   `VAD` = Virtual Address Descriptor. Describes the region in the process tree. Result → structure `v28..v35`.
7. **Large Pages check**
   Sets `v26` if Large Pages are needed.

### How Memory Partition Processing Works

```c
PVOID64 partitionHandle = *((_QWORD *)&v24 + 1);

if (partitionHandle != NULL)
{
    if (partitionHandle == MEMORY_EXISTING_VAD_PARTITION_HANDLE) // -3
    {
        // Use existing VAD
        v9 = 1;  // partition = system
        v18 = 1;
    }
    else
    {
        // Open the specified partition by handle
        // Memory partitions — isolation of physical memory pools.... 
        // Used in containers / Like a Hyper-V
        v15 = PsReferencePartitionByHandle(
            partitionHandle,
            MEMORY_PARTITION_MODIFY_ACCESS, // 2
            PreviousMode,
            ‘lVmM’,           // tag for debugging
            &v18              // → partition pointer
        );
        v9 = v18;
        
        if (v15 < 0) goto cleanup;
    }
}
```

In short → Memory Partition is:
An isolated pool of physical memory.
Used in:
- Docker
- Hyper-V VM
- QoS (Sensitive tbh)
  
Pseudo-handles:
- `-1` `MEMORY_CURRENT_PARTITION_HANDLE` → current process partition
- `-2` `MEMORY_SYSTEM_PARTITION_HANDLE` → system partition
- `-3` `MEMORY_EXISTING_VAD_PARTITION_HANDLE` → use VAD

### Checking Large Pages compatibility

```c
// v26 is set if Large Pages are requested
// Check: flags must contain MEM_PHYSICAL (0x400000)
// but not MEM_LARGE_PAGES | MEM_PHYSICAL simultaneously without MEM_PHYSICAL

if ((_BYTE)v26 && (AllocationType & 0x20400000) != 0x400000)
{
    v15 = STATUS_INVALID_PARAMETER;
    goto LABEL_23;
}

// Correct combination for Large Pages:
//   MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES
//   AllocationType & 0x20400000 must be = 0x20000000 (LARGE_PAGES only)
//   or = 0x20400000 (LARGE_PAGES | PHYSICAL for 64K pages)
```

---

## In conclusion
`MiAllocateVirtualMemory` → Performs the actual memory allocation.
It searches for a free VA range, creates a VAD node (the `_MMVAD` structure is added to the `EPROCESS` AVL tree), which is useful to know in order to rent the AVL tree for VAD Unlinking.

At `MEM_COMMIT`:
- The process's CommittedPages counter is updated
- Space is reserved in the pagefile
- PTEs remain “demand-zero” until the first access

When the page is accessed for the first time:
- Page Fault Handler is triggered
- A real physical frame is allocated
- PTE is updated with the real PFN

With `MEM_LARGE_PAGES | MEM_COMMIT`:
- Physical pages are allocated IMMEDIATELY :)
- Contiguous 2MB blocks of physical memory are required
- PTEs are configured with the Large Page flag

The release occurs due to the part in `LABEL_14`, where the number of counters for partitioning is reduced (`PsDereferencePartition(v9);`).
And:
```c
if (Object[0])
    ObfDereferenceObjectWithTag(Object[0], 'mVmM');
```

---

## Return codes

| Code | Value | Description |
| :--- | :--- | :--- |
| `STATUS_SUCCESS` | `0x00000000` | Success (Unexpected during VAD Unlinking) |
| `STATUS_INVALID_PARAMETER` | `0xC000000D` | Invalid flags/parameters |
| `STATUS_NO_MEMORY` | `0xC0000017` | No memory |
| `STATUS_COMMITMENT_LIMIT` | `0xC000012D` | Commit limit exhausted |
| `STATUS_ACCESS_DENIED` | `0xC0000022` | No rights to process |
| `STATUS_INVALID_HANDLE` | `0xC0000008` | Invalid handle |
| `STATUS_CONFLICTING_ADDRESSES`| `0xC0000018` | Address is busy |
| `STATUS_ACCESS_VIOLATION` | `0xC0000005` | Invalid pointer |
| `STATUS_PRIVILEGE_NOT_HELD` | `0xC0000061` | No `SeLockMemoryPrivilege` |

---

## VAD just lives here
Specifically, each call to `NtAllocateVirtualMemory` creates a VAD node in `EPROCESS`.
The `EPROCESS` structure is a transition of steps → `VadRoot: _RTL_AVL_TREE`, → `VAD: 0x10000-0x1FFFF`, → ...\\\...?\\

That is, for correct processing there:
- `StartingVpn` / `EndingVpn` → address range
- `Flags` → Private/Mapped/Image
- `ControlArea` → pointer to section (if mapped)
- `u.VadFlags.Protection` → `PAGE_*` rights
- `u.VadFlags.MemCommit` → whether memory is fixed

So, our analysis has come to an end, what a fun hierarchy!

### PoC for PLACEHOLDER_MEM:

```c
// Create a large placeholder
PVOID baseAddr = NULL;
SIZE_T totalSize = 16 * 1024 * 1024;  // 16MB

NtAllocateVirtualMemory(
    NtCurrentProcess(),
    &baseAddr,
    0,
    &totalSize,
    MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
    PAGE_NOACCESS // EXCEPTION???
);

// Split into 4MB chunks
// Free the first 4MB, preserving the placeholder structure
PVOID splitAddr = baseAddr;
SIZE_T splitSize = 4 * 1024 * 1024;

NtFreeVirtualMemory(
    NtCurrentProcess(),
    &splitAddr,
    &splitSize,
    MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER
);

// Now:
// [PLACEHOLDER 4MB] [PLACEHOLDER 12MB]
// You can replace the first piece with a real section
NtMapViewOfSectionEx(
    sectionHandle,
    NtCurrentProcess(),
    &splitAddr,  // exact address!
    &sectionOffset,
    &splitSize,
    MEM_REPLACE_PLACEHOLDER,
    PAGE_READWRITE,
    NULL, 0
);
```
