import mongoose from "mongoose";


const userSchema = new mongoose.Schema({
    Fullname: {type: String},
    Companyname: {type: String},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    verifyOTP: {type: String, default: ''},
    verifyOTPExpireAt: {type: Number, default: 0},
    isAccountVerified: {type: Number, default: false},
    resetOTP: {type: String, default: ''},
    resetOTPExpireAt: {type: Number, default: 0},
})


const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;