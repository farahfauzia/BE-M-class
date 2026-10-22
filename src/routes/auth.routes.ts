import { Router } from "express";
import { deleteMe, getMe, login, logout, register, updateMe } from "../controllers/auth.controller";
import { authenticate, authorizeRoles } from "../middlewares/auth";

const router = Router();

router.post("/register", register);
router.post("/login", (req, res) => login(["student"], req, res));
router.post("/admin/login", (req, res) => login(["admin", "teacher"], req, res));
const authenticatedUser = [authenticate, authorizeRoles("student", "admin", "teacher")];

router.get("/me", ...authenticatedUser, getMe);
router.patch("/me", ...authenticatedUser, updateMe);
router.delete("/me", ...authenticatedUser, deleteMe);
router.post("/logout", ...authenticatedUser, logout);

export default router;
