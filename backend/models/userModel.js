const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      require: [true, "Please Add a name"],
    },
    email: {
      type: String,
      require: [true, "Please Add a name"],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter a valid email",
      ],
    },
    password: {
      type: String,
      require: [true, "Please Add a password"],
      minLength: [6, "Password must be upto 6 character"],
      //   maxLength: [23, "Password must be less than 23 characters"],
    },
    photo: {
      type: String,
      required: [true, "Please add a photo"],
      default: "thgrtbjrbj",
    },
    phone: {
      type: String,
      default: "+91",
    },
    bio: {
      type: String,
      maxLength: [250, "Bio must be less than 23 characters"],
      default: "Bio",
    },
  },
  {
    timestamps: true,
  }
);

//Encrypt password before saving to DB
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  //Hash Password
  const salts = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salts);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model("user", userSchema);

module.exports = User;
