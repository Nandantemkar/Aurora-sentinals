import { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { registerUser, verifyOTP, loginUser, getUserById, comparePassword, hashPassword } from '../services/auth';
import { generateAccessToken, generateRefreshToken } from '../utils/jwt';
import { supabaseAdmin } from '../db/supabaseAdmin';

export const register = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('role').optional().isIn(['student', 'security']),
  
  async (req: Request, res: Response): Promise<void> => {
    res.status(400).json({ error: 'Sign up is handled by Supabase. Please use the frontend registration form.' });
  },
];

export const verify = [
  body('userId').notEmpty(),
  body('otp').isLength({ min: 6, max: 6 }),
  
  async (req: Request, res: Response): Promise<void> => {
    res.json({ message: 'Email verification is now handled by Supabase.' });
  },
];

export const createLocalUser = [
  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Email must be a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('role')
    .notEmpty().withMessage('Role is required')
    .isIn(['student', 'security']).withMessage('Role must be either "student" or "security"'),
  
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Log incoming request for debugging
      console.log("CREATE LOCAL USER REQUEST:", {
        hasEmail: !!req.body.email,
        hasPassword: !!req.body.password,
        hasRole: !!req.body.role,
        roleValue: req.body.role
      });

      // Validate request body
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(err => {
          const field = 'param' in err ? err.param : 'unknown';
          return `${field}: ${err.msg}`;
        }).join(', ');
        console.log("CREATE LOCAL USER VALIDATION ERROR:", errorMessages, errors.array());
        res.status(400).json({ 
          message: "Validation failed", 
          errors: errors.array(),
          details: errorMessages
        });
        return;
      }

      // Extract and validate fields from request body
      const { email, password, role } = req.body;
      
      // Additional validation check (after express-validator)
      if (!email || typeof email !== 'string') {
        console.log("CREATE LOCAL USER ERROR: Invalid email", { email, type: typeof email });
        res.status(400).json({ 
          message: "Email is required and must be a string"
        });
        return;
      }

      if (!password || typeof password !== 'string') {
        console.log("CREATE LOCAL USER ERROR: Invalid password", { hasPassword: !!password, type: typeof password });
        res.status(400).json({ 
          message: "Password is required and must be a string"
        });
        return;
      }

      if (!role || typeof role !== 'string') {
        console.log("CREATE LOCAL USER ERROR: Invalid role", { role, type: typeof role });
        res.status(400).json({ 
          message: "Role is required and must be a string"
        });
        return;
      }

      if (role !== 'student' && role !== 'security') {
        console.log("CREATE LOCAL USER ERROR: Invalid role value", { role });
        res.status(400).json({ 
          message: "Role must be either 'student' or 'security'"
        });
        return;
      }

      // Normalize email (lowercase and trim)
      const normalizedEmail = email.toLowerCase().trim();
      
      // Ensure password is a string (no modification)
      const passwordString = String(password);

      console.log("CREATE LOCAL USER: Processing", { 
        email: normalizedEmail, 
        role, 
        passwordLength: passwordString.length 
      });

      // Check if user already exists locally
      const { data: existingUser, error: checkError } = await supabaseAdmin
        .from('users')
        .select('id')
        .eq('email', normalizedEmail)
        .maybeSingle();

      if (checkError && checkError.code !== 'PGRST116') {
        // PGRST116 = not found, which is fine
        console.error("CREATE LOCAL USER ERROR: Database check failed", checkError);
        res.status(500).json({ message: "Failed to check if user exists" });
        return;
      }

      if (existingUser) {
        console.log("CREATE LOCAL USER ERROR: User already exists", normalizedEmail);
        res.status(409).json({ message: "User already exists in local database" });
        return;
      }

      // Hash the password using bcrypt.hash (single hash, not double)
      console.log("CREATE LOCAL USER: Hashing password...");
      const passwordHash = await hashPassword(passwordString);
      
      if (!passwordHash || typeof passwordHash !== 'string') {
        console.error("CREATE LOCAL USER ERROR: Password hash failed or invalid", { 
          hasHash: !!passwordHash, 
          hashType: typeof passwordHash 
        });
        res.status(500).json({ message: "Failed to hash password" });
        return;
      }

      console.log("CREATE LOCAL USER: Password hashed successfully, hash length:", passwordHash.length);

      // Create user in local database
      const { data: user, error: insertError } = await supabaseAdmin
        .from('users')
        .insert({
          email: normalizedEmail,
          password_hash: passwordHash,
          role: role,
          is_verified: false, // Will be set to true after email verification
        })
        .select()
        .single();

      if (insertError) {
        console.error("CREATE LOCAL USER ERROR: Database insert failed", insertError);
        res.status(500).json({ 
          message: "Failed to create local user",
          error: insertError.message
        });
        return;
      }

      if (!user) {
        console.error("CREATE LOCAL USER ERROR: User not returned after insert");
        res.status(500).json({ message: "Failed to create local user" });
        return;
      }

      console.log("CREATE LOCAL USER SUCCESS:", { 
        id: user.id, 
        email: user.email, 
        role: user.role 
      });
      
      res.status(201).json({
        message: "Local user created successfully",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error: any) {
      console.error("CREATE LOCAL USER ERROR: Unexpected error", error);
      res.status(500).json({ 
        message: "Failed to create local user",
        error: error.message || "Internal server error"
      });
    }
  },
];

export const login = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  
  async (req: Request, res: Response): Promise<void> => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ message: "Validation failed", errors: errors.array() });
        return;
      }

      const { email, password } = req.body;
      const normalizedEmail = email.toLowerCase();

      console.log("LOGIN ATTEMPT: Starting login for", normalizedEmail);

      // Step 1: Retrieve user via SupabaseAdmin email lookup
      // Note: getUserByEmail doesn't exist, using listUsers with email filter
      const { data: usersList, error: adminError } = await supabaseAdmin.auth.admin.listUsers();
      
      if (adminError) {
        console.log("LOGIN FAILURE: Supabase lookup failed");
        res.status(500).json({
          message: "Server error verifying account"
        });
        return;
      }

      // Step 2: Verify the user exists in Supabase Auth
      const supabaseUser = usersList?.users?.find(u => u.email?.toLowerCase() === normalizedEmail);
      
      if (!supabaseUser) {
        console.log("LOGIN FAILURE: User not found");
        res.status(404).json({
          message: "User not found"
        });
        return;
      }

      // Step 3: Verify email_confirmed_at is NOT null
      if (!supabaseUser.email_confirmed_at) {
        console.log("LOGIN FAILURE: Email not verified");
        res.status(400).json({
          message: "Email not verified yet. Please check your inbox."
        });
        return;
      }

      // Step 4: Retrieve the corresponding user from the local database
      const { data: localUser, error: dbError } = await supabaseAdmin
        .from('users')
        .select('*')
        .eq('email', normalizedEmail)
        .single();

      if (dbError && dbError.code !== 'PGRST116') { // PGRST116 = not found
        console.log("LOGIN FAILURE: Database lookup error");
        res.status(500).json({
          message: "Server error retrieving user data"
        });
        return;
      }

      let finalUser: any;
      let userRole: 'student' | 'security';

      // Step 5: Validate the password using ONLY local database
      if (!localUser) {
        console.log("LOGIN FAILURE: User not found in local database");
        res.status(401).json({
          message: "Invalid email or password"
        });
        return;
      }

      // Verify password with local hash
      console.log("LOGIN: User found in local DB, verifying password");
      const passwordMatch = await comparePassword(password, localUser.password_hash);
      
      if (!passwordMatch) {
        console.log("LOGIN FAILURE: Password mismatch");
        res.status(401).json({
          message: "Invalid email or password"
        });
        return;
      }
      
      console.log("LOGIN: Password verified, user authenticated");
      finalUser = localUser;
      userRole = localUser.role;

      // Step 6: Generate and return JWT
      console.log("LOGIN: Generating JWT tokens for user", finalUser.id);
      const payload = {
        userId: finalUser.id,
        email: finalUser.email,
        role: userRole,
      };

      const accessToken = generateAccessToken(payload);
      const refreshToken = generateRefreshToken(payload);

      // Set refresh token as HTTP-only cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.json({
        user: {
          id: finalUser.id,
          email: finalUser.email,
          role: userRole,
        },
        accessToken,
      });
    } catch (error: any) {
      console.log("LOGIN FAILURE: Unexpected error -", error.message || error);
      res.status(500).json({ message: "Login failed" });
    }
  },
];

export const me = async (req: Request, res: Response): Promise<void> => {
  try {
    // This endpoint requires authentication middleware
    const userId = (req as any).user?.id;
    if (!userId) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const user = await getUserById(userId);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        is_verified: user.is_verified,
      },
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};
