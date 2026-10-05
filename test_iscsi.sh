#!/bin/sh
# QuickiSCSI test suite - run on Debian client (10.0.0.53)
# Server is at 10.0.0.36

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; }
skip() { TOTAL=$((TOTAL+1)); echo "  SKIP: $1"; }

echo "========================================="
echo " QuickiSCSI Test Suite"
echo "========================================="

# --- Test 1: Session active ---
echo ""
echo "[1] Session active"
if iscsiadm -m session | grep -q "iqn.homelab:ramdisk"; then
    pass "Session active"
else
    fail "No active session"
fi

# --- Test 2: Disk visible ---
echo ""
echo "[2] Disk visible"
if lsblk | grep -q "^sdb"; then
    SIZE=$(lsblk -bnd /dev/sdb | awk '{print $1}')
    echo "  Disk size: $SIZE bytes"
    pass "Disk sdb visible"
else
    fail "Disk sdb not visible"
fi

# --- Test 3: Read/write small block ---
echo ""
echo "[3] Read/write small block (dd)"
dd if=/dev/urandom of=/tmp/iscsi_wtest bs=512 count=1 2>/dev/null
dd if=/dev/sdb of=/tmp/iscsi_rtest bs=512 count=1 2>/dev/null
dd if=/tmp/iscsi_wtest of=/dev/sdb bs=512 count=1 2>/dev/null
dd if=/dev/sdb of=/tmp/iscsi_rtest2 bs=512 count=1 2>/dev/null
if cmp -s /tmp/iscsi_wtest /tmp/iscsi_rtest2; then
    pass "512-byte write+read roundtrip"
else
    fail "512-byte write+read mismatch"
fi
rm -f /tmp/iscsi_wtest /tmp/iscsi_rtest /tmp/iscsi_rtest2

# --- Test 4: Large sequential write ---
echo ""
echo "[4] Large sequential write (10MB)"
dd if=/dev/zero of=/dev/sdb bs=1M count=10 2>&1 | tail -1
if [ $? -eq 0 ]; then
    pass "10MB sequential write"
else
    fail "10MB sequential write"
fi

# --- Test 5: Format ext4 + mount ---
echo ""
echo "[5] Format ext4 and mount"
mkfs.ext4 -F /dev/sdb 2>/dev/null
if [ $? -eq 0 ]; then
    pass "mkfs.ext4 succeeded"
else
    fail "mkfs.ext4 failed"
fi

mkdir -p /tmp/iscsi_mount
mount /dev/sdb /tmp/iscsi_mount 2>/dev/null
if [ $? -eq 0 ]; then
    pass "Mount succeeded"
else
    fail "Mount failed"
fi

# --- Test 6: File operations ---
echo ""
echo "[6] File operations"
echo "hello from iscsi" > /tmp/iscsi_mount/testfile.txt 2>/dev/null
CONTENT=$(cat /tmp/iscsi_mount/testfile.txt 2>/dev/null)
if [ "$CONTENT" = "hello from iscsi" ]; then
    pass "File write + read"
else
    fail "File content mismatch: '$CONTENT'"
fi

mkdir /tmp/iscsi_mount/testdir 2>/dev/null
if [ -d /tmp/iscsi_mount/testdir ]; then
    pass "Directory creation"
else
    fail "Directory creation"
fi

# --- Test 7: Large file write ---
echo ""
echo "[7] Large file write (50MB)"
dd if=/dev/urandom of=/tmp/iscsi_mount/bigfile bs=1M count=50 2>&1 | tail -1
if [ -f /tmp/iscsi_mount/bigfile ]; then
    SZ=$(stat -c%s /tmp/iscsi_mount/bigfile)
    if [ "$SZ" = "52428800" ]; then
        pass "50MB file written correctly"
    else
        fail "50MB file size mismatch: $SZ"
    fi
else
    fail "50MB file not created"
fi

# --- Test 8: Data integrity (remount) ---
echo ""
echo "[8] Data integrity after remount"
umount /tmp/iscsi_mount 2>/dev/null
sleep 1
mount /dev/sdb /tmp/iscsi_mount 2>/dev/null
if [ -f /tmp/iscsi_mount/testfile.txt ] && [ -f /tmp/iscsi_mount/bigfile ]; then
    pass "Files survive remount"
else
    fail "Files lost after remount"
fi

# --- Cleanup ---
umount /tmp/iscsi_mount 2>/dev/null
rmdir /tmp/iscsi_mount 2>/dev/null

echo ""
echo "========================================="
echo " Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "========================================="
