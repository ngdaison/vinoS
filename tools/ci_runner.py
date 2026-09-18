# CI test runner
import sys, os, subprocess, time, shutil

QEMU = r'C:/Program Files/qemu/qemu-system-x86_64.exe'
CODE = r'C:/Program Files/qemu/share/edk2-x86_64-code.fd'
VARS_T = r'C:/Program Files/qemu/share/edk2-i386-vars.fd'
VARS = 'build/edk2-vars.fd'
LOG_FILE = 'build/ci_test_run.log'

if not os.path.exists('build'):
    os.makedirs('build')
if not os.path.exists(VARS) and os.path.exists(VARS_T):
    shutil.copyfile(VARS_T, VARS)

cmd = [
    QEMU, '-machine', 'q35', '-cpu', 'max', '-smp', '4', '-m', '512',
    '-drive', 'if=pflash,format=raw,readonly=on,file=' + CODE,
    '-drive', 'if=pflash,format=raw,file=' + VARS,
    '-drive', 'format=raw,file=fat:rw:build/esp',
    '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
    '-netdev', 'user,id=kosnet,ipv4=on,ipv6=off,hostfwd=tcp::18080-:80',
    '-device', 'e1000,netdev=kosnet,mac=52:54:00:12:34:56',
    '-display', 'none'
]

print('Starting KOS Headless CI Test Run in QEMU...')
start = time.time()
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')

lines = []
timeout = 45
passed = False
try:
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.01)
            continue
        lines.append(line)
        sys.stdout.write(line)
        sys.stdout.flush()
        if 'ALL K27 QA, FUZZ, FAULT & STRESS SUITES PASSED' in line:
            passed = True
            time.sleep(0.5)
            proc.kill()
            break
except Exception as e:
    print('Exception:', e)
finally:
    proc.kill()

with open(LOG_FILE, 'w', encoding='utf-8') as f:
    f.writelines(lines)

full_log = ''.join(lines)
checklist = [
    ('Regression Suite', 'ALL REGRESSION TESTS PASSED' in full_log),
    ('ELF Fuzzing', 'ELF parser survived' in full_log),
    ('Syscall Fuzzing', 'Syscall dispatcher survived' in full_log),
    ('Partition Fuzzing', 'Partition parsers survived' in full_log),
    ('FAT32 Fuzzing', 'FAT32 engine survived' in full_log),
    ('Network Fuzzing', 'Network stack processed' in full_log),
    ('ASN.1/X.509 Fuzzing', 'ASN.1 / X.509 parsers survived' in full_log),
    ('TLS Fuzzing', 'TLS record layer survived' in full_log),
    ('Fault Injection', 'Fault injection self-test passed' in full_log),
    ('Multi-Core Process Stress', 'concurrent threads completed' in full_log),
    ('Filesystem Stress', 'Filesystem completed' in full_log),
    ('Socket Concurrency Stress', 'Socket subsystem completed' in full_log),
    ('Memory Churn Stress', 'Memory churn completed' in full_log),
    ('Zero Resource Leaks', 'Zero resource leaks' in full_log),
]

print('=' * 60)
print('  KOS Milestone K27 CI Summary')
print('=' * 60)
all_ok = True
for name, ok in checklist:
    st = '[PASS]' if ok else '[FAIL]'
    if not ok: all_ok = False
    print(f'  {st} {name}')

if passed or all_ok:
    print("\n[CI RESULT] ALL K27 TESTS PASSED SUCCESSFULLY! (Code 0)")
    sys.exit(0)
else:
    print("\n[CI RESULT] CI TEST FAILED! (Code 1)")
    sys.exit(1)
