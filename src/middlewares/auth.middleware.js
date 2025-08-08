import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        if (!token) {
            throw new ApiError(401, "Valid Authorization Token Parameter is required", ["Valid Authorization Token Parameter is required"])
        }
    
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
        if (!user) {
            throw new ApiError(401, "Authorization Token Parameter is invalid", ["Authorization Token Parameter is invalid"])
        }
    
        req.user = user
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Authorization Token Parameter is invalid", ["Authorization Token Parameter is invalid"])
    }
})