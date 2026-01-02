import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const SeekerRegister = async (req, res)=>{

    const {Fullname, email, password} = req.body;

    if(!Fullname || !email || !password){
        return res.json({success: false, message: 'Missing Details'});
    }

    try{
        const existingUser = await userModel.findOne({email});

        if(existingUser){
            return res.json({ success: false, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({Fullname, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'WELCOME to OnTask',
            text: `Welcome to OnTask website, YOur account has been created with email id: ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});
    } 
    catch(error){
        res.json({success: false, message: error.message});
    }
}



export const ProviderRegister = async (req, res)=>{

    const {Companyname, email, password} = req.body;

    if(!Companyname || !email || !password){
        return res.json({success: false, message: 'Missing Details'});
    }

    try{
        const existingUser = await userModel.findOne({email});

        if(existingUser){
            return res.json({ success: false, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({Companyname, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'WELCOME to OnTask',
            text: `Welcome to OnTask website, YOur account has been created with email id: ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});
    } 
    catch(error){
        res.json({success: false, message: error.message});
    }
}



export const login =  async (req, res)=> {
    
    const {email, password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and password are required'});
    }

    try{

        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success: false, message: 'Invalid email'});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.json({success: false, message: 'Invalid password'});
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({success: true});

    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}


export const logout = async (req, res)=> {
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: 'Logged Out'});
    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}


// Send Verification OTP to the User's Email
export const sendVerifyOTP = async (req, res)=>{
    try{

        const userId = req.userId;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account Already verified"})
        }

        const OTP = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOTP = OTP;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verififcation OTP',
            text: `Your OTP is ${OTP}. Verify your account using this OTP.`
        }
        await transporter.sendMail(mailOption);

        res.json({ success: true, message: 'Verification OTP sent on Email' });
    }
    catch(error){
        res.json({ success: false, message: error.message });
    }
}


//Verify email using OTP
export const verifyEmail = async (req, res)=>{

    const userId = req.userId;
    const {OTP} = req.body;

    if(!userId || !OTP){
        return res.json({ success: false, message: 'Missing Details' });
    }

    try{
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({ success: false, message: 'User not found' });
        }

        if(user.verifyOTP === '' || user.verifyOTP !== OTP){
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if(user.verifyOTPExpireAt < Date.now()){
            return res.json({ success: false, message: 'OTP Expired' });
        }

        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: 'Email verified successfully' })

    }
    catch(error){
        res.json({ success: false, message: error.message });
    }
}


//Authentication of user
export const isAuthenticated = async (req, res)=>{
    try{
        return res.json({ success: true });
    }
    catch(error){
        res.json({ success: false, message: error.message });
    }
}


//Send Password Reset OTP
export const sendResetOTP = async (req, res)=>{
    const {email} = req.body;

    if(!email){
        return res.json({ succes: false, message: 'Email is required' });
    }

    try{
        
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: 'User not found' });
        }

        const OTP = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOTP = OTP;
        user.resetOTPExpireAt = Date.now() + 3 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for reset password is ${OTP}. Use this OTP to reset your login password.`
        };

        await transporter.sendMail(mailOption);
        return res.json({ success: true, message: 'OTP sent to your email' });

    }
    catch(error){
        return res.json({ success: false, message: error.message });
    }
}


//reset password
export const resetPassword = async (req, res)=>{
    const {email, OTP, newPassword} = req.body;

    if(!email || !OTP || !newPassword){
        return res.json({ success: false, message: 'Email, OTP and new password are required' });
    }

    try{

        const user = await userModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: 'User not found' });
        }

        if(user.resetOTP === "" || user.resetOTP !== OTP){
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if(user.resetOTPExpireAt < Date.now()){
            return res.json({ success: false, message: 'OTP Expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: 'Password has been reset successfully' });
        
    }
    catch(error){
        return res.json({ success: false, message: error.message });
    }
}