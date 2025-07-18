import dotenv from "dotenv";
import connectDB from "./db/database.js";
import { app } from "./app.js";

dotenv.config({
    path: "./env"
})

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(`Server is running on : ${process.env.PORT}`);
        
    })
})
.catch((error) => {
    console.log("MONGO DB Connection Failed!!", error);    
})







// import express from "express";

// const app = express();

// ;( async () => {
//     try {
//         await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//         app.on("error", (error) => {
//             console.log("ERROR: ", error);
//             throw error;
//         })

//         app.listen(process.env.PORT, () => {
//             console.log(`APP is listing on :, ${process.env.PORT}`);
//         })

//     } catch(error) {
//         console.error("ERROR: ", error)
//         throw err
//     }
// })()