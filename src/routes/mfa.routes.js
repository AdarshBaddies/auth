import { Router } from "express";
import { 
  setupMFA, 
  verifyMFA, 
  enableMFA, 
  disableMFA, 
  generateBackupCodes, 
  getMFAStatus 
} from "../controllers/mfa.controller.js";
import { requireAuth } from "../middlewares/auth.js";
import { validateMFA } from "../middlewares/validation.js";

const router = Router();

// All MFA routes require authentication
router.use(requireAuth);

// MFA setup and management
router.post("/setup", setupMFA);
router.post("/verify", validateMFA, verifyMFA);
router.post("/enable", validateMFA, enableMFA);
router.post("/disable", validateMFA, disableMFA);
router.post("/backup-codes", generateBackupCodes);
router.get("/status", getMFAStatus);

export default router;
