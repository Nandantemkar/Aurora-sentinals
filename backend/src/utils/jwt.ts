
import dotenv from 'dotenv';
import jwt, { Secret, SignOptions } from "jsonwebtoken";



dotenv.config();

const accessSecret: Secret = process.env.JWT_ACCESS_SECRET!;
const refreshSecret: Secret = process.env.JWT_REFRESH_SECRET!;


if (!accessSecret) {
  throw new Error("JWT_ACCESS_SECRET is not defined");
}

if (!refreshSecret) {
  throw new Error("JWT_REFRESH_SECRET is not defined");
}
const accessExpiry: SignOptions["expiresIn"] =
  (process.env.JWT_ACCESS_EXPIRY as SignOptions["expiresIn"]) ?? "15m";

const refreshExpiry: SignOptions["expiresIn"] =
  (process.env.JWT_REFRESH_EXPIRY as SignOptions["expiresIn"]) ?? "7d";



export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

export function generateAccessToken(payload: TokenPayload): string {
  return jwt.sign(
    payload,
    accessSecret as string,
    { expiresIn: accessExpiry }
  );

}

export function generateRefreshToken(payload: TokenPayload): string {
  return jwt.sign(payload, refreshSecret as string, {
    expiresIn: refreshExpiry,
  });
}

export function verifyAccessToken(token: string): TokenPayload {
  try {
    const decoded = jwt.verify(token, accessSecret);

    if (typeof decoded === "string") {
      throw new Error("Invalid token payload");
    }

    return decoded as TokenPayload;
  } catch (error) {
    throw new Error("Invalid or expired access token");
  }
}

export function verifyRefreshToken(token: string): TokenPayload {
  try {
    const decoded = jwt.verify(token, refreshSecret);

    if (typeof decoded === "string") {
      throw new Error("Invalid token payload");
    }

    return decoded as TokenPayload;
  } catch (error) {
    throw new Error("Invalid or expired refresh token");
  }
}
