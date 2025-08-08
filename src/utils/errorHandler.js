import { ApiError } from "./ApiError.js";

const errorHandler = (err, _, res, next) => {
    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({
            status: err.statusCode,
            errors: err.errors || [],
            message: err.message
        });
    }

    return res.status(500).json({
            status: 500,
            message: "Internal Server Error!",
            errors: err.stack
        });
}

export { errorHandler }