import express from 'express';
import { isAuthenticated, login, logout, resetPassword, ProviderRegister, SeekerRegister, sendResetOTP, sendVerifyOTP, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';


const authRouter = express.Router();

authRouter.post('/SeekerRegister', SeekerRegister);
authRouter.post('/ProviderRegister', ProviderRegister);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOTP);
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.post('/is-auth', userAuth, isAuthenticated);
authRouter.post('/sent-reset-otp', sendResetOTP);
authRouter.post('/reset-password', resetPassword);


export default authRouter;