const jwt = require('jsonwebtoken');
const ApiError = require('../exceptions/api-error');
require('dotenv').config();

module.exports = function (req, res, next) {
  try {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
      console.log('Authorization header is missing');
      return next(
        ApiError.UnauthorizedError('Authorization header is missing'),
      );
    }

    const tokenParts = authorizationHeader.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
      console.log('Invalid authorization format');
      return next(ApiError.UnauthorizedError('Invalid authorization format'));
    }

    const accessToken = tokenParts[1];
    if (!accessToken) {
      console.log('Access token is missing');
      return next(ApiError.UnauthorizedError('Access token is missing'));
    }

    try {
      console.log('Received access token:', accessToken);
      const userData = jwt.verify(accessToken, process.env.SECRET_KEY);
      console.log('Token is valid, user data:', userData);
      req.user = userData;
      next();
    } catch (error) {
      console.error('JWT verification error:', error);
      return next(ApiError.UnauthorizedError('Invalid access token'));
    }
  } catch (error) {
    console.error('Authorization failed:', error);
    return next(ApiError.UnauthorizedError('Authorization failed'));
  }
};
