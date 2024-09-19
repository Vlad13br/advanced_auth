const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const uuid = require('uuid');
const jwt = require('jsonwebtoken');
const UserModel = require('../models/user-model');
const tokenModel = require('../models/token-model');
const ApiError = require('../exceptions/api-error');

class UserController {
  async registration(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return next(ApiError.BadRequest('Validation error', errors.array()));
      }

      const { email, password } = req.body;
      const candidate = await UserModel.findOne({ email });
      if (candidate) {
        throw ApiError.BadRequest(`User with email ${email} already exists`);
      }

      const hashedPassword = await bcrypt.hash(password, 5);
      const activationLink = uuid.v4();
      const user = await UserModel.create({
        email,
        password: hashedPassword,
        activationLink,
      });

      const accessToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '4h',
        },
      );

      const refreshToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '30d',
        },
      );

      const tokenData = await tokenModel.findOne({ user: user._id });
      if (tokenData) {
        tokenData.refreshToken = refreshToken;
        await tokenData.save();
      } else {
        await tokenModel.create({ user: user._id, refreshToken });
      }

      res.cookie('refreshToken', refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      });
      return res.json({
        accessToken,
        refreshToken,
        user: { id: user._id, email: user.email },
      });
    } catch (error) {
      next(error);
    }
  }

  async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const user = await UserModel.findOne({ email });
      if (!user) {
        throw ApiError.BadRequest('User not found');
      }

      const isPassEquals = await bcrypt.compare(password, user.password);
      if (!isPassEquals) {
        throw ApiError.BadRequest('Wrong password');
      }

      const accessToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '4h',
        },
      );
      const refreshToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '30d',
        },
      );

      const tokenData = await tokenModel.findOne({ user: user._id });
      if (tokenData) {
        tokenData.refreshToken = refreshToken;
        await tokenData.save();
      } else {
        await tokenModel.create({ user: user._id, refreshToken });
      }

      res.cookie('refreshToken', refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      });
      return res.json({
        accessToken,
        refreshToken,
        user: { id: user._id, email: user.email },
      });
    } catch (error) {
      next(error);
    }
  }

  async logout(req, res, next) {
    try {
      const { refreshToken } = req.cookies;
      const tokenData = await tokenModel.deleteOne({ refreshToken });
      res.clearCookie('refreshToken');
      return res.json(tokenData);
    } catch (error) {
      next(error);
    }
  }

  async refresh(req, res, next) {
    try {
      const { refreshToken } = req.cookies;
      if (!refreshToken) {
        throw ApiError.UnauthorizedError();
      }

      const userData = jwt.verify(refreshToken, process.env.SECRET_KEY);
      const tokenFromDB = await tokenModel.findOne({ refreshToken });
      if (!userData || !tokenFromDB) {
        throw ApiError.UnauthorizedError();
      }

      const user = await UserModel.findById(userData.id);

      const accessToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '4h',
        },
      );
      const newRefreshToken = jwt.sign(
        { id: user._id, email: user.email },
        process.env.SECRET_KEY,
        {
          expiresIn: '30d',
        },
      );

      tokenFromDB.refreshToken = newRefreshToken;
      await tokenFromDB.save();

      res.cookie('refreshToken', newRefreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      });
      return res.json({
        accessToken,
        refreshToken: newRefreshToken,
        user: { id: user._id, email: user.email },
      });
    } catch (error) {
      next(error);
    }
  }

  async getUsers(req, res, next) {
    try {
      const users = await UserModel.find();
      res.json(users);
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new UserController();
