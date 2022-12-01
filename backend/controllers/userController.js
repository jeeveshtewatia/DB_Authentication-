const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

//Register User
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all required fields");
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 character");
  }

  // check if user email already exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email has already been registered");
  }

  //Encrypt pssword before saving to DB    // Moved to userModel
  //   const salts = await bcrypt.genSalt(10);
  //   const hashedPassword = await bcrypt.hash(password, salts);

  //Create new user

  const user = await User.create({
    name,
    email,
    // password: hashedPassword,
    password,
  });

  //Generate Token
  const token = generateToken(user._id);

  //Send HTTP- Only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //It's 1 day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }

  // if (!req.body.email) {
  //     res.status(400);
  //     throw new Error("Please add an email");
  //   }
  //   res.send("Register User");
});

// LOgin User
const loginUser = asyncHandler(async (req, res) => {
  //   res.send("LOgin User");

  const { email, password } = req.body;

  //Validate Request
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add Email and Password");
  }
  //Check if user exists in our DB
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("user not fount ,please signUp");
  }

  //If User exist ,check if password is correct

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  //Generate Token
  const token = generateToken(user._id);

  //Send HTTP- Only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //It's 1 day
    sameSite: "none",
    secure: true,
  });

  if (user && passwordIsCorrect) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid email or password");
  }
});

//Logout User

const logout = asyncHandler(async (req, res) => {
  //   res.send("Logout user");
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), //It's 1 day
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({
    message: "Successfully Logged Out",
  });
});

//Get User Data
const getUser = asyncHandler(async (req, res) => {
  //   res.send("get user data");
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
    });
  } else {
    res.status(400);
    throw new Error("User Not Found");
  }
});

//Get Login Status
const loginStatus = asyncHandler(async (req, res) => {
  // res.send("User status found");
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  //Verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

//Update User Details
const updateUser = asyncHandler(async (req, res) => {
  //   res.send("user updated");
  const user = await User.findById(req.user._id);

  console.log(user);
  if (user) {
    const { name, email, photo, phone, bio } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    // console.log(updatedUser);
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      phone: updatedUser.phone,
      email: updatedUser.email,
      photo: updatedUser.photo,
      bio: updatedUser.bio,
    });
  } else {
    res.status(404);
    throw new Error("User Not Found");
  }
});

const changePassword = asyncHandler(async (req, res) => {
  //   res.send("password changed");
  const user = await User.findById(req.user._id);
  const { oldPassword, password } = req.body;

  if (!user) {
    res.status(400);
    throw new Error("User not Found,please sign Up");
  }
  //Validate
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please add old and new password");
  }

  //check if password matches password in DB
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  //Save new Password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).send("Password change Successfil");
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }
});

//forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  //   res.send("fogot password");
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  //Delete token if it exists in Db
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //Create Reset Token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;

  //   console.log(resetToken);
  //Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  //   console.log(hashedToken);

  //Save token to DB

  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), //Thisry minutes
  }).save();

  //Construct reaset Url

  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  //Reset Email

  const message = `
  <h2>Hello ${user.name}<h2>
  <p> Please use the url below to reset your password</p>
  <p>This reset link in valid only for 30mins</p> 
  
  <a href=${resetUrl} clicktracking=off > ${resetUrl} </a> 
  
  <p>Regards... </p>
  <p>Jeevesh Tewatia </p>`;

  const subject = "Password Reset Request";
  const send_to = user.email;
  const send_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, send_from);
    res.status(200).json({ success: true, message: "Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("email Not Sent,Please try again");
  }

  //   res.send("forgots password");
});

//Reset Password

const resetPassword = asyncHandler(async (req, res) => {
  //   res.send("Reset Password");

  const { password } = req.body;
  const { resetToken } = req.params;

  //Hash token ,then compare to Token ib DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //find token in DB

  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid token");
  }

  //Find the user
  const user = await User.findOne({ _id: userToken.userId });

  user.password = password;
  await user.save();
  res.status(200).json({
    message: "Password reset successful, Please Login",
  });
});
module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
