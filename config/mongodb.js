import mongoose from "mongoose";

// use pooling
const connectDB = async ()=>{

    mongoose.connection.on('connected', ()=>console.log("Database Connected"));

    await mongoose.connect(`${process.env.MONGODB_URI}/Mern_auth`)
};

export default connectDB;