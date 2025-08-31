import { Router } from "express";
import { requireAuth, requireRoles } from "../middlewares/auth.js";

const router = Router();

// All user routes require authentication
router.use(requireAuth);

// Get user profile
router.get("/profile", (req, res) => {
  res.json({
    success: true,
    data: {
      user: {
        id: req.user.id,
        email: req.user.email,
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        role: req.user.role,
        status: req.user.status,
        email_verified: req.user.email_verified,
        mfa_enabled: req.user.mfa_enabled,
        profile_picture_url: req.user.profile_picture_url,
        created_at: req.user.created_at,
        updated_at: req.user.updated_at
      }
    }
  });
});

// Update user profile
router.put("/profile", (req, res) => {
  // TODO: Implement profile update logic
  res.json({
    success: true,
    message: "Profile update endpoint - to be implemented"
  });
});

// Change password
router.put("/password", (req, res) => {
  // TODO: Implement password change logic
  res.json({
    success: true,
    message: "Password change endpoint - to be implemented"
  });
});

// Delete account
router.delete("/account", (req, res) => {
  // TODO: Implement account deletion logic
  res.json({
    success: true,
    message: "Account deletion endpoint - to be implemented"
  });
});

// Admin routes
router.get("/admin/users", requireRoles("admin"), (req, res) => {
  // TODO: Implement admin user list
  res.json({
    success: true,
    message: "Admin user list endpoint - to be implemented"
  });
});

export default router;
