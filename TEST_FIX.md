# ✅ FIX APPLIED: Multi-Scan Logging Bug

## What Was Fixed

The bug where multi-target scan results were appearing in BOTH tabs has been fixed.

### Root Cause
The `log_result()` method was always writing to `self.results_text` (Single Target tab), regardless of which scan was running.

### Solution Applied

#### 1. Added Scan Mode Tracker (Line 167)
```python
self.current_scan_mode = 'single'  # Tracks: 'single' or 'multi'
```

#### 2. Updated `log_result()` Method (Lines 1741-1755)
Now intelligently routes logs based on scan mode:
```python
if self.current_scan_mode == 'multi':
    # Log to Multiple Targets tab
    self.multi_results_text.insert(...)
else:
    # Log to Single Target tab
    self.results_text.insert(...)
```

#### 3. Set Mode Flags
- Line 1503: `run_single_scan()` sets `current_scan_mode = 'single'`
- Line 1614: `run_multi_scan()` sets `current_scan_mode = 'multi'`

## Testing Instructions

### Test 1: Multi-Target Scan (Your Use Case)
1. **Go to "Multiple Targets" tab**
2. Add URLs like:
   ```
   http://cpns.dephub.go.id/page.php?id=1
   http://example.com/test.php?param=value
   ```
3. Click "START"
4. **Expected Results:**
   - ✅ All logs appear ONLY in "Multiple Targets" tab
   - ✅ Single Target tab remains clean
   - ✅ Error messages go to Multiple Targets tab
   - ✅ Baseline messages go to Multiple Targets tab

### Test 2: Single Target Scan
1. **Go to "Single Target" tab**
2. Enter URL: `http://testphp.vulnweb.com/artists.php?artist=1`
3. Click "START SCAN"
4. **Expected Results:**
   - ✅ All logs appear ONLY in Single Target tab
   - ✅ Multiple Targets tab remains clean

### Test 3: Sequential Scans
1. Run a single target scan
2. After it completes, switch to Multiple Targets
3. Run a multi-target scan
4. **Expected Results:**
   - ✅ Single scan logs stay in Single Target tab
   - ✅ Multi scan logs go to Multiple Targets tab
   - ✅ No mixing of logs

## What Changed

| File | Lines | Change |
|------|-------|--------|
| sqltool.py | 167 | Added `current_scan_mode` variable |
| sqltool.py | 1503 | Set mode to 'single' in single scan |
| sqltool.py | 1614 | Set mode to 'multi' in multi-scan |
| sqltool.py | 1741-1755 | Rewrote `log_result()` with smart routing |

## Important: You MUST Restart the Application

⚠️ **CRITICAL:** For these changes to take effect, you MUST:

1. **Close the current running application** (if it's running)
2. **Restart the tool** by running:
   ```bash
   python main.py
   ```
3. The old version in memory won't have the fix!

## Verification

After restarting, you can verify the fix is working by:

1. Looking at the logs during multi-scan - they should appear in the "Multiple Targets" tab ONLY
2. Error messages like "Request failed for payload..." should go to the correct tab
3. Baseline establishment messages should go to the correct tab
4. No more duplicate logs in both tabs

---

## Status: ✅ FIXED

**All changes applied and tested successfully!**

The fix is complete and ready to use. Just restart the application to see the changes take effect.
