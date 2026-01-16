# 🔧 Fix Both Issues

## Issue 1: Schema Error ✅ FIXED

**Error**: `relation "idx_users_email" already exists`

**Cause**: Schema was partially run before, indexes already exist

**Solution**: Use the fixed schema file that drops indexes first

### Steps:

1. **Go to Supabase Dashboard → SQL Editor**
2. **Click "New Query"**
3. **Open**: `backend/src/db/schema_fixed.sql`
4. **Copy ALL contents** (the entire file)
5. **Paste** into Supabase SQL Editor
6. **Click "Run"**

This version uses `DROP INDEX IF EXISTS` first, so it won't error if indexes already exist.

---

## Issue 2: Backend Error ⚠️ NEEDS CHECK

**Error**: `"Failed to create user: TypeError: fetch failed"`

**Cause**: Backend might not be connecting to Supabase properly

**Possible reasons:**
1. Backend not restarted after creating `.env` file
2. Supabase credentials wrong in `.env`
3. Network/firewall blocking Supabase connection

### Steps to Fix:

#### 1. Restart Backend Server (REQUIRED!)

1. **Stop backend** (Ctrl+C in terminal)
2. **Start it again**:
   ```powershell
   cd backend
   npm run dev
   ```

3. **Check for errors**:
   - Should NOT see: "WARNING: Supabase credentials not configured"
   - Should see: "🚀 Aurora Sentinel Backend running on port 3001"
   - Check for any Supabase connection errors

#### 2. Verify .env File

Check that `backend/.env` has correct credentials:
```
SUPABASE_URL=https://uszrynkltqxddwiytbnp.supabase.co
SUPABASE_KEY=sb_publishable_qJZ4qrX1UyNZrI_lT5Pv9g_7isoMvd4
SUPABASE_SERVICE_KEY=sb_secret_Vpgg2RkoqX2qTtd38Thkyw_6-dRbBNZ
```

#### 3. Test Connection

After restarting, try registering again. If you still get the error:

1. **Check backend console** for error messages
2. **Check Supabase Dashboard** → Settings → API to verify keys
3. **Verify project is active** in Supabase

---

## Quick Action Plan

1. ✅ **Run `schema_fixed.sql` in Supabase** (fixes schema error)
2. ✅ **Restart backend server** (loads .env file)
3. ✅ **Test registration** again

---

**Run the fixed schema and restart backend - that should fix both issues!** 🚀
