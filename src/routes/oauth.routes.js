import { Router } from "express";
import passport from "passport";
import { 
  googleAuth, 
  facebookAuth, 
  appleAuth, 
  linkOAuthAccount, 
  unlinkOAuthAccount 
} from "../controllers/oauth.controller.js";
import { requireAuth } from "../middlewares/auth.js";

const router = Router();

// Google OAuth routes
router.get("/google", passport.authenticate("google", { 
  scope: ["profile", "email"] 
}));

router.get("/google/callback", 
  passport.authenticate("google", { failureRedirect: "/login" }), 
  googleAuth
);

// Facebook OAuth routes
router.get("/facebook", passport.authenticate("facebook", { 
  scope: ["email"] 
}));

router.get("/facebook/callback", 
  passport.authenticate("facebook", { failureRedirect: "/login" }), 
  facebookAuth
);

// Apple OAuth routes
router.get("/apple", passport.authenticate("apple"));

router.post("/apple/callback", 
  passport.authenticate("apple", { failureRedirect: "/login" }), 
  appleAuth
);

// OAuth account management (requires authentication)
router.post("/link", requireAuth, linkOAuthAccount);
router.delete("/unlink/:provider", requireAuth, unlinkOAuthAccount);

export default router;


