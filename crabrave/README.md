# Crab Rave
## _Difficultty: Hard_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/crabrave/crab_rave_easier.7z)
### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/crabrave/crab_rave_harder.7z)
### _password: infected_

## Analysis

Contents of the easier  archive
```
2023-10-10 12:40:50 DR..A            0            0  crab_rave_easier
2023-10-10 12:40:26 ....A         2151          640  crab_rave_easier/company_financial_report_SAFE_NO_VIRUSES.csv.lnk
2023-10-09 23:12:38 ..H.A     13216242      2733104  crab_rave_easier/ntcheckos.dll
```

NB: As I am not that confident of my skills I'm going the easier way :)

Checking the `lnk` file shows how the dll is loaded
```
$ cat company_financial_report_SAFE_NO_VIRUSES.csv.lnk
...
C:\Windows\System32\rundll32.exe ntcheckos.dll,DLLMain
...
```

Next step is to load the dll in Binary Ninja and try to decompile it (https://binary.ninja/)

![](https://github.com/nikip72/huntress-2023/blob/main/crabrave/BinaryNinja1.png)

From there we see that DLLMain() just calls NtCheckOSArchitecture()
```
1000b4f0  int64_t DLLMain()
1000b4f4      NtCheckOSArchitecture()
1000b4ff      return 0
```

Main flow is implemented in NtCheckOSArchitecture()
```
1000add0  int64_t NtCheckOSArchitecture()

1000ae15      int64_t var_90
1000ae15      crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_90, &data_103cd938, 0xe, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
1000ae3b      int64_t var_78
1000ae3b      crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_78, &data_103cd946, 0xa, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
1000ae4a      void* rax = __rust_alloc(0x40, 8)
1000ae52      if (rax == 0)
1000b460          alloc::alloc::handle_alloc_error::h46b3ca24fe8858b3(0x40, 8)
1000b460          noreturn
1000ae6d      int128_t var_c8
1000ae6d      int128_t* var_88
1000ae6d      uint64_t* var_80
1000ae6d      alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, var_88, var_80)
1000ae77      void* var_b8
1000ae77      void* var_98 = var_b8
1000ae7c      int128_t zmm0 = var_c8
1000ae88      int64_t var_b0 = 0
1000aea9      int128_t* var_70
1000aea9      uint64_t* var_68
1000aea9      alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, var_70, var_68)
1000aeb3      *(rax + 0x38) = var_b8
1000aebc      *(rax + 0x28) = var_c8
1000aec0      int128_t zmm0_1 = var_b0.o
1000aecc      *(rax + 0x10) = zmm0
1000aed1      *rax = zmm0_1
1000aed5      *(rax + 0x20) = 1
1000aedd      int64_t var_60 = 2
1000aee9      void* var_58 = rax
1000aef1      int64_t var_50 = 2
1000af01      char rax_4
1000af01      void* rsi_1
1000af01      if (*rax == 0)
1000af3f          whoami::platform::username::h2bf89a8bc02175c5(&var_b0)
1000af44          int128_t* rsi = zmm0.q
1000af56          alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, rsi, zmm0:8.q)
1000af5b          int64_t rdx_3 = var_b0
1000af63          if (rdx_3 != 0)
1000af72              __rust_dealloc(rsi, rdx_3, not.q(rdx_3) u>> 0x3f)
1000af77          rsi_1 = var_c8:8.q
1000af8c          rax_4 = _$LT$$RF$str$u20$as$u20$...$::is_contained_in::h925ca508a6f23175(*(rax + 0x10), *(rax + 0x18), rsi_1, var_b8)
1000af08      else
1000af08          whoami::platform::hostname::h78ff8a263b76e7ff(&var_b0)
1000af0d          int128_t* i_4 = zmm0.q
1000af12          uint64_t* r8_2 = zmm0:8.q
1000af1a          if (r8_2 != 0)
1000af20              char* i_2 = i_4
1000af27              if (r8_2 u< 8)
1000af27                  goto label_1000b0ad
1000af31              void* rax_3
1000af31              int32_t _.rdata_1[0x4]
1000af31              int32_t zmm1_1[0x4]
1000af31              int128_t zmm2_1
1000af31              int32_t zmm3_1[0x4]
1000af31              if (r8_2 u>= 0x20)
1000af99                  rax_3 = r8_2 & 0xffffffffffffffe0
1000af9d                  int64_t rcx_9 = 0
1000af9f                  _.rdata_1 = _.rdata
1000afa7                  zmm1_1 = data_103cd5f0
1000afaf                  zmm2_1 = data_103cd600
1000b015                  do
1000afc0                      zmm3_1 = *(i_4 + rcx_9)
1000afc5                      int32_t zmm4_1[0x4] = *(i_4 + rcx_9 + 0x10)
1000afcf                      int32_t temp0_1[0x4] = _mm_add_epi8(zmm3_1, _.rdata_1)
1000afd7                      int32_t temp0_2[0x4] = _mm_add_epi8(zmm4_1, _.rdata_1)
1000afe7                      int32_t zmm7_1[0x4] = _mm_cmpeq_epi8(_mm_min_epu8(temp0_1, zmm1_1), temp0_1) & zmm2_1
1000afff                      int32_t zmm5_1[0x4] = (_mm_cmpeq_epi8(_mm_min_epu8(temp0_2, zmm1_1), temp0_2) & zmm2_1) | zmm4_1
1000b003                      *(i_4 + rcx_9) = zmm7_1 | zmm3_1
1000b008                      *(i_4 + rcx_9 + 0x10) = zmm5_1
1000b00e                      rcx_9 = rcx_9 + 0x20
1000b00e                  while (rax_3 != rcx_9)
1000b024                  if (r8_2 != rax_3 && (r8_2.b & 0x18) == 0)
1000b089                      i_2 = rax_3 + i_4
1000b0ad                      label_1000b0ad:
1000b0ad                      void* i
1000b0ad                      do
1000b090                          char rdx_7 = *i_2
1000b0a1                          *i_2 = (rdx_7 - 0x41 u< 0x1a) << 5 | rdx_7
1000b0a3                          i = &i_2[1]
1000b0a7                          i_2 = i
1000b0a7                      while (i != i_4 + r8_2)
1000af33              else
1000af33                  rax_3 = nullptr
1000b024              if (r8_2 u< 0x20 || (r8_2 u>= 0x20 && r8_2 != rax_3 && (r8_2.b & 0x18) != 0))
1000b029                  void* rdx_6 = r8_2 & 0xfffffffffffffff8
1000b02d                  i_2 = i_4 + rdx_6
1000b031                  _.rdata_1 = data_103cd610
1000b039                  zmm1_1 = data_103cd620
1000b041                  zmm2_1 = *"        "
1000b07d                  do
1000b050                      zmm3_1 = *(i_4 + rax_3)
1000b059                      int32_t temp0_7[0x4] = _mm_add_epi8(zmm3_1, _.rdata_1)
1000b071                      *(i_4 + rax_3) = ((_mm_cmpeq_epi8(_mm_max_epu8(temp0_7, zmm1_1), temp0_7) & not.o(zmm2_1)) | zmm3_1)[0].q
1000b076                      rax_3 = rax_3 + 8
1000b076                  while (rdx_6 != rax_3)
1000b082                  if (r8_2 != rdx_6)
1000b082                      goto label_1000b0ad
1000b0b7          alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, i_4, r8_2)
1000b0bc          int64_t rdx_9 = var_b0
1000b0c4          if (rdx_9 != 0)
1000b0d3              __rust_dealloc(i_4, rdx_9, not.q(rdx_9) u>> 0x3f)
1000b0d8          rsi_1 = var_c8:8.q
1000b0ed          rax_4 = _$LT$$RF$str$u20$as$u20$...$::is_contained_in::h925ca508a6f23175(*(rax + 0x10), *(rax + 0x18), rsi_1, var_b8)
1000b0f4      int64_t rdx_11 = var_c8.q
1000b0fc      if (rdx_11 != 0)
1000b10b          __rust_dealloc(rsi_1, rdx_11, not.q(rdx_11) u>> 0x3f)
1000b112      if (rax_4 != 0)
1000b11d          char rax_9
1000b11d          char* rsi_3
1000b11d          if (*(rax + 0x20) == 0)
1000b15b              whoami::platform::username::h2bf89a8bc02175c5(&var_b0)
1000b160              int128_t* rsi_2 = zmm0.q
1000b172              alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, rsi_2, zmm0:8.q)
1000b177              int64_t rdx_13 = var_b0
1000b17f              if (rdx_13 != 0)
1000b18e                  __rust_dealloc(rsi_2, rdx_13, not.q(rdx_13) u>> 0x3f)
1000b193              rsi_3 = var_c8:8.q
1000b1a8              rax_9 = _$LT$$RF$str$u20$as$u20$...$::is_contained_in::h925ca508a6f23175(*(rax + 0x30), *(rax + 0x38), rsi_3, var_b8)
1000b124          else
1000b124              whoami::platform::hostname::h78ff8a263b76e7ff(&var_b0)
1000b129              int128_t* i_5 = zmm0.q
1000b12e              uint64_t* r8_15 = zmm0:8.q
1000b136              if (r8_15 != 0)
1000b13c                  char* i_3 = i_5
1000b143                  if (r8_15 u< 8)
1000b143                      goto label_1000b2cd
1000b14d                  void* rax_8
1000b14d                  int32_t _.rdata_2[0x4]
1000b14d                  int32_t zmm1_2[0x4]
1000b14d                  int128_t zmm2_2
1000b14d                  int32_t zmm3_2[0x4]
1000b14d                  if (r8_15 u>= 0x20)
1000b1b5                      rax_8 = r8_15 & 0xffffffffffffffe0
1000b1b9                      int64_t rcx_19 = 0
1000b1bb                      _.rdata_2 = _.rdata
1000b1c3                      zmm1_2 = data_103cd5f0
1000b1cb                      zmm2_2 = data_103cd600
1000b235                      do
1000b1e0                          zmm3_2 = *(i_5 + rcx_19)
1000b1e5                          int32_t zmm4_2[0x4] = *(i_5 + rcx_19 + 0x10)
1000b1ef                          int32_t temp0_10[0x4] = _mm_add_epi8(zmm3_2, _.rdata_2)
1000b1f7                          char zmm6_2[0x10] = _mm_add_epi8(zmm4_2, _.rdata_2)
1000b207                          int32_t zmm7_2[0x4] = _mm_cmpeq_epi8(_mm_min_epu8(temp0_10, zmm1_2), temp0_10) & zmm2_2
1000b21f                          int32_t zmm5_2[0x4] = (_mm_cmpeq_epi8(_mm_min_epu8(zmm6_2, zmm1_2), zmm6_2) & zmm2_2) | zmm4_2
1000b223                          *(i_5 + rcx_19) = zmm7_2 | zmm3_2
1000b228                          *(i_5 + rcx_19 + 0x10) = zmm5_2
1000b22e                          rcx_19 = rcx_19 + 0x20
1000b22e                      while (rax_8 != rcx_19)
1000b244                      if (r8_15 != rax_8 && (r8_15.b & 0x18) == 0)
1000b2a9                          i_3 = rax_8 + i_5
1000b2cd                          label_1000b2cd:
1000b2cd                          void* i_1
1000b2cd                          do
1000b2b0                              char rdx_17 = *i_3
1000b2c1                              *i_3 = (rdx_17 - 0x41 u< 0x1a) << 5 | rdx_17
1000b2c3                              i_1 = &i_3[1]
1000b2c7                              i_3 = i_1
1000b2c7                          while (i_1 != i_5 + r8_15)
1000b14f                  else
1000b14f                      rax_8 = nullptr
1000b244                  if (r8_15 u< 0x20 || (r8_15 u>= 0x20 && r8_15 != rax_8 && (r8_15.b & 0x18) != 0))
1000b249                      void* rdx_16 = r8_15 & 0xfffffffffffffff8
1000b24d                      i_3 = i_5 + rdx_16
1000b251                      _.rdata_2 = data_103cd610
1000b259                      zmm1_2 = data_103cd620
1000b261                      zmm2_2 = *"        "
1000b29d                      do
1000b270                          zmm3_2 = *(i_5 + rax_8)
1000b279                          int32_t temp0_16[0x4] = _mm_add_epi8(zmm3_2, _.rdata_2)
1000b291                          *(i_5 + rax_8) = ((_mm_cmpeq_epi8(_mm_max_epu8(temp0_16, zmm1_2), temp0_16) & not.o(zmm2_2)) | zmm3_2)[0].q
1000b296                          rax_8 = rax_8 + 8
1000b296                      while (rdx_16 != rax_8)
1000b2a2                      if (r8_15 != rdx_16)
1000b2a2                          goto label_1000b2cd
1000b2d7              alloc::str::_$LT$impl$u2...$GT$::to_lowercase::hd285174da2bcbd0c(&var_c8, i_5, r8_15)
1000b2dc              int64_t rdx_19 = var_b0
1000b2e4              if (rdx_19 != 0)
1000b2f3                  __rust_dealloc(i_5, rdx_19, not.q(rdx_19) u>> 0x3f)
1000b2f8              rsi_3 = var_c8:8.q
1000b30d              rax_9 = _$LT$$RF$str$u20$as$u20$...$::is_contained_in::h925ca508a6f23175(*(rax + 0x30), *(rax + 0x38), rsi_3, var_b8)
1000b314          int64_t rdx_21 = var_c8.q
1000b31c          if (rdx_21 != 0)
1000b32b              __rust_dealloc(rsi_3, rdx_21, not.q(rdx_21) u>> 0x3f)
1000b332          if (rax_9 != 0)
1000b356              crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_c8, &data_103cd950, 0xb, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
1000b35b              void* rsi_4 = var_c8:8.q
1000b36d              crab_rave::inject_flag::h5274a20ed59aab7d(&var_b0, rsi_4, var_b8)
1000b372              void* rcx_26 = zmm0.q
1000b37a              if (rcx_26 != 0)
1000b37c                  int64_t rdx_23 = var_b0
1000b384                  if (rdx_23 != 0)
1000b390                      __rust_dealloc(rcx_26, rdx_23, not.q(rdx_23) u>> 0x3f)
1000b395              int64_t rdx_24 = var_c8.q
1000b39d              if (rdx_24 != 0)
1000b3ac                  __rust_dealloc(rsi_4, rdx_24, not.q(rdx_24) u>> 0x3f)
1000b3b1      int64_t rdx_25 = *(rax + 8)
1000b3b8      if (rdx_25 != 0)
1000b3c8          __rust_dealloc(*(rax + 0x10), rdx_25, not.q(rdx_25) u>> 0x3f)
1000b3cd      int64_t rdx_26 = *(rax + 0x28)
1000b3d4      if (rdx_26 != 0)
1000b3e4          __rust_dealloc(*(rax + 0x30), rdx_26, not.q(rdx_26) u>> 0x3f)
1000b3f7      int64_t rax_13 = __rust_dealloc(rax, 0x40, 8)
1000b3fc      int64_t rdx_27 = var_78
1000b407      if (rdx_27 != 0)
1000b416          rax_13 = __rust_dealloc(var_70, rdx_27, not.q(rdx_27) u>> 0x3f)
1000b41b      int64_t rdx_28 = var_90
1000b423      if (rdx_28 != 0)
1000b432          rax_13 = __rust_dealloc(var_88, rdx_28, not.q(rdx_28) u>> 0x3f)
1000b455      return rax_13
```

Several things are to be noted here:

- some calls to crab_rave::litcrypt_internal::decrypt_bytes at address `c8a0`
- calls to whoami::platform::username and whoami::platform::hostname
- function crab_rave::inject_flag that supposingly will give up the flag at address with offset of `b36d` in NtCheckOSArchitecture()

Assumption is that the code does some checks based on the username & hostname and if valid calls `inject_flag`. We can try to decrypt the required values (and later did it), but for now the strategy is to patch the code in a debugger and skip all the checks. To do that we need to trace the execution and (assuming that decrypt_bytes calls are vital) after the first two calls to jump to address `b356` at the next decrypt_bytes call so it can decrypt whatever needs to be decrypted and call inject_flag.

To do that a simple program is needed to load the dll and call the entry function, then break and patch the code.

Code to load the dll:
```
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <wchar.h>
#include <string>


typedef int(*MyFunctionType)();

int main()
{

    //LPCWSTR dllName = "ntcheckos.dll";
    std::string userInput;
    HINSTANCE hDll = LoadLibrary(_T("ntcheckos.dll"));

        if (hDll != NULL) {

            MyFunctionType myFunction = reinterpret_cast<MyFunctionType>(GetProcAddress(hDll, "NtCheckOSArchitecture"));
            if (myFunction != NULL) {
            std::cout << "Press enter to execute func" << std::endl;
            std::getline(std::cin, userInput);

                int result = myFunction();
                std::cout << "Result: " << result << std::endl;
            }
            else {
                std::cout << "Failed to get function" << std::endl;
            }

            FreeLibrary(hDll);
        }
        else {
            std::cout << "Failed to load dll" << std::endl;
        }

        return 0;
}
```

After compilation load the program in `x64dbg` (https://x64dbg.com/)
![](https://github.com/nikip72/huntress-2023/blob/main/crabrave/x64dbg1.png)

First two calls to `c8a0` correspond to 
```
1000ae15      crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_90, &data_103cd938, 0xe, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
1000ae3b      crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_78, &data_103cd946, 0xa, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
```
followed by __rust_aloc()
```
1000ae4a      void* rax = __rust_alloc(0x40, 8)
```
From the decompiled code. As we might need them, step over. Then at `ae4f-ae52`
```
test rax,rax
je ntcheckos.6AD7B456
```

That jump is not taken. We binary patch it to:
```
jne ntcheckos.6AD7B334
```

As `b334` is the address of parameter initialization for next crab_rave::litcrypt_internal::decrypt_bytes call.
```
1000b356              crab_rave::litcrypt_internal::decrypt_bytes::h32388621a43d3c14(&var_c8, &data_103cd950, 0xb, "-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…", 0x42)
```

Confirmed by disassembly in Binary Ninja

![](https://github.com/nikip72/huntress-2023/blob/main/crabrave/BinaryNinja2.png)

crab_rave::inject_flag is reached and the flag is revealed

![](https://github.com/nikip72/huntress-2023/blob/main/crabrave/flag.png)

NB:

crab_rave::litcrypt_internal::decrypt_bytes actually performs XOR decrypt of the memory region specified in the call with a key '"-rr5-rr5-rr5-rr5-rr5-rr5-rr5-rr5…"'
decrypting calls reveal the username (m.yeomans30801), machine name (WIN-DEV-13) and gist (https://gist.githubusercontent.com/HuskyHacks/8cece878fde615ef8770059d88211b2e/raw/abcaf5920a40843851eec550d1dca97e9444ac75/gistfile1.txt) with data to be downloaded and decrypted by the crab_rave::inject_flag function



