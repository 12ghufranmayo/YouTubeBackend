import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

//CORS Settings
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}));

app.use(express.json({limit: "16kb"})); //to set form data limit
app.use(express.urlencoded({extended: true, limit: "16kb"})); // to encode urls and limit urls
app.use(express.static("public")); // to save assets like images
app.use(cookieParser()); // to connect with browser secure cookies

import userRouter from "./routes/user.routes.js";
import { errorHandler } from "./utils/errorHandler.js";

// Use middleware for prefix of route
app.use("/api/v1/users", userRouter);

app.use(errorHandler);

export {app}