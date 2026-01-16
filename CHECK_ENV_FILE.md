# 🔍 Check .env File Format

## Common .env File Issues

### Issue 1: File Extension
❌ **Wrong**: `backend/env.txt` or `backend/.env.txt`  
✅ **Correct**: `backend/.env` (starts with dot, NO extension)

### Issue 2: Quotes Around Values
❌ **Wrong**: 
```
SUPABASE_URL="https://uszrynkltqxddwiytbnp.supabase.co"
```
✅ **Correct**:
```
SUPABASE_URL=https://uszrynkltqxddwiytbnp.supabase.co
```
**No quotes needed!** (Most .env parsers handle this, but avoid quotes to be safe)

### Issue 3: Spaces Around Equals
❌ **Wrong**: `SUPABASE_URL = https://...`  
✅ **Correct**: `SUPABASE_URL=https://...`  
**No spaces around the `=` sign!**

### Issue 4: Extra Spaces/Blank Lines
❌ **Wrong**: Lines with trailing spaces, or empty lines with spaces  
✅ **Correct**: Clean lines, no trailing spaces

### Issue 5: File Encoding
❌ **Wrong**: UTF-8 with BOM  
✅ **Correct**: UTF-8 (without BOM) or ASCII

## How to Verify Your .env File

1. **File Location**: `C:\Users\jeetp\aurora-sentinel\backend\.env`

2. **File Format**:
   - Starts with a dot: `.env` (not `env` or `.env.txt`)
   - No file extension
   - In the `backend` folder

3. **Content Format** (example):
   ```
   SUPABASE_URL=https://uszrynkltqxddwiytbnp.supabase.co
   SUPABASE_KEY=sb_publishable_qJZ4qrX1UyNZrI_lT5Pv9g_7isoMvd4
   SUPABASE_SERVICE_KEY=sb_secret_Vpgg2RkoqX2qTtd38Thkyw_6-dRbBNZ
   ```
   - No quotes around values
   - No spaces around `=`
   - One key=value per line

4. **Check in File Explorer**:
   - Enable "Show hidden files" in Windows Explorer
   - Should see `.env` file (might appear without icon)

## Quick Fix

If you think the file is wrong:

1. **Open** `backend/ENV_SETUP.txt`
2. **Copy ALL content**
3. **Delete** old `backend/.env` file
4. **Create new** `backend/.env` file
5. **Paste** content (make sure no extra quotes/spaces)
6. **Save**
7. **Restart backend**

---

**Most common issue: File named `.env.txt` instead of `.env`** ⚠️
