import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/couldinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
    const {fullName, email, username, password} = req.body;
    
    if ([fullName, email, username, password].some((field) => !field || field?.trim() === "")) {
        throw new ApiError(400, "All fields are required", ["All fields are required"]);
    }

    const existedUser = await User.findOne({
        $or: [{ email }, { username }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists", ["User with email or username already exists"])
    }

    const avatarLocalPath   = req.files && Array.isArray(req.files.avatar) && req.files.avatar.length > 0 ? 
    req.files?.avatar[0]?.path : undefined;
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required" ,["Avatar file is required"]);
    }

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length  > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    const avatar        = await uploadOnCloudinary(avatarLocalPath);
    const coverImage    = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required");
    }

    const user  = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    });

    const createdUser = await User.findById(user._id).select("-password -refreshToken");
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering user.", ["Something went wrong while registering user."])
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully.")
    )
})

const generateAccessandRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken   = user.generateAccessToken()
        const refreshToken  = user.generateRefreshToken()
        
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh Tokens")
    }
}

const loginUser = asyncHandler(async (req, res) => {
    const {email, username, password} = req.body;

    if (!(email || username)) {
        throw new ApiError(400, "username or email is required" , ["username or email is required"])
    }

    const user = await User.findOne({
        $or: [{email, username}]
    });

    if (!user) {
        throw new ApiError(404, "user does not exist", ["user does not exist"])
    }

    if(!password) {
        throw new ApiError(400, "password is required", ["password is required"]);
    }

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new ApiError(401, "password is invalid", ["password is invalid"])
    }

    const {accessToken, refreshToken} = await generateAccessandRefreshTokens(user._id)

    const loggedInUser = await User.findOne(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200, {user: loggedInUser, accessToken, refreshToken}, "User LoggedIn Successfully")
    )
})

const logoutUser    = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, 
        {
            $set: {
                refreshToken: null
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken
    
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Valid Refresh Token Parameter is required", ["Valid Refresh Token Parameter is required"]);
        }
    
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "Refresh Token Parameter is invalid", ["Refresh Token Parameter is invalid"])
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expird or used", ["Refresh token is expird or used"])
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessandRefreshTokens(user?._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(200, {accessToken, refreshToken: newRefreshToken}, "Access token refreshed successfully")
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token", [error?.message || "Invalid refresh token"]);
    }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken }