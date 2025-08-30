import User from "../models/User.js";
import {
  signAccessToken,
  signRefreshToken,
  cookieOptions,
  verifyRefreshToken,
} from "../utils/jwt.js";
import bcrypt from "bcrypt";

const buildAuthResponse = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

export const register = async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "Email already in use" });

    const user = await User.create({ name, email, password, role });
    const payload = { sub: user._id.toString(), role: user.role };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    user.refreshTokenHash = refreshTokenHash;
    await user.save();

    res
      .cookie("refresh_token", refreshToken, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 })
      .status(201)
      .json({ token: accessToken, user: buildAuthResponse(user) });
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select("+password +refreshTokenHash name email role createdAt updatedAt");
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const match = await user.comparePassword(password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const payload = { sub: user._id.toString(), role: user.role };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await user.save();

    res
      .cookie("refresh_token", refreshToken, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 })
      .json({ token: accessToken, user: buildAuthResponse(user) });
  } catch (err) {
    next(err);
  }
};

export const me = async (req, res) => {
  return res.json({ user: buildAuthResponse(req.user) });
};

export const refresh = async (req, res, next) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ message: "No refresh token" });
    const decoded = verifyRefreshToken(token);
    const user = await User.findById(decoded.sub).select("+refreshTokenHash name email role createdAt updatedAt");
    if (!user || !user.refreshTokenHash) return res.status(401).json({ message: "Invalid refresh" });
    const valid = await bcrypt.compare(token, user.refreshTokenHash);
    if (!valid) return res.status(401).json({ message: "Invalid refresh" });

    const payload = { sub: user._id.toString(), role: user.role };
    const accessToken = signAccessToken(payload);
    const newRefresh = signRefreshToken(payload);
    user.refreshTokenHash = await bcrypt.hash(newRefresh, 10);
    await user.save();

    res
      .cookie("refresh_token", newRefresh, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 })
      .json({ token: accessToken, user: buildAuthResponse(user) });
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    if (req.user) {
      const user = await User.findById(req.user._id).select("+refreshTokenHash");
      if (user) {
        user.refreshTokenHash = undefined;
        await user.save();
      }
    }
    res.clearCookie("refresh_token", { ...cookieOptions, maxAge: 0 });
    return res.status(204).send();
  } catch (err) {
    next(err);
  }
};

