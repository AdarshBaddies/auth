import { Router } from "express";
import { 
  register, 
  login, 
  me, 
  logout, 
  refresh, 
  verifyEmail, 
  forgotPassword, 
  resetPassword 
} from "../controllers/auth.controller.js";
import { requireAuth } from "../middlewares/auth.js";
import { 
  validateRegistration, 
  validateLogin, 
  validateForgotPassword, 
  validateResetPassword 
} from "../middlewares/validation.js";

const router = Router();

// Public routes
router.post("/register", validateRegistration, register);
router.post("/login", validateLogin, login);
router.post("/refresh", refresh);
router.post("/forgot-password", validateForgotPassword, forgotPassword);
router.post("/reset-password", validateResetPassword, resetPassword);
router.get("/verify-email/:token", verifyEmail);

// Protected routes
router.get("/me", requireAuth, me);
router.post("/logout", requireAuth, logout);

export default router;

