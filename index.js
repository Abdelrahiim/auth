const express = require("express");
const morgan = require("morgan"); // for logging request information
const z = require("zod");  // for validation it is the fastest most powerful validation library
// npm install zod
const passport = require('passport'); // for authentication with passport npm install passport
const JwtStrategy = require('passport-jwt').Strategy; // JwtStrategy for authentication npm install passport-jwt
const ExtractJwt = require('passport-jwt').ExtractJwt; // ExtractJwt for authentication 
const jwt = require('jsonwebtoken'); // for creating and verifying tokens npm install jsonwebtoken


const bcrypt = require("bcrypt");

const connectDB = require("./connectDB");

// Connect To Mongo DB
require("dotenv").config();

const User = require("./Model/UserModel");

const port = process.env.PORT || 3000;
const app = express();

// middleware
app.use(express.urlencoded({ extended: false })); // for parsing application/x-www-form-urlencoded
app.use(express.json()); // for parsing application/json
app.use(morgan("dev"))
app.use(passport.initialize()); // initialize passport for authentication

const secretKey = process.env.JWT_SECRET || "secret";



const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // extract the token from the request header 
  secretOrKey: secretKey // secretOrKey for authentication should be in .env file should be a long random string
}

// setting up passport with JWT strategy to extract the token from the request and verify it
passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
  try {
    const user = await User.findById(payload.sub).select("-password"); // find user in the database based on the Id extracted from the token and remove the password
    if (user) {
      return done(null, user); // put the user in the request object if the user is found
    } else {
      return done(null, false); // return false if the user is not found
    }
  } catch (err) {
    return done(err, false);
  }
}))

connectDB();
// zod validation for create user 
const createUserZodSchema = z.object({
  email: z.string().email(), // email must be a valid email
  password: z.string().regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/), //password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and be at least 8 characters long
  firstname: z.string().optional(), // all the other fields are optional
  lastname: z.string().optional(),
  age: z.number().optional(),
  gender: z.string().optional(),
  address: z.string().optional(),
  phone: z.string().optional(),
  image: z.string().optional(),
})

// create user API endpoint
app.post("/sign-up", async (req, res) => {
  const body = req.body; // get the request body Object
  try {
    const result = createUserZodSchema.safeParse(body); // validate the body with zod schema we created
    // in case of an error validation return 400 bad request with message and error description
    if (!result.success) {
      return res.status(400).json({
        message: "Validation error",
        error: result.error.flatten().fieldErrors(),
      })
    }
    const { password, ...rest } = result.data; // extract password and rest of the data 
    const hashedPassword = await bcrypt.hash(password, 10); // hash the password
    const user = new User({ ...rest, password: hashedPassword }); // create user in the database
    await user.save();
    // TODO : make the email unique
    return res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
})

// sign in API endpoint
const signInZodSchema = z.object({
  email: z.string().email(),
  password: z.string().regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/),
})

// sign in API endpoint
app.post("/login", async (req, res) => {
  const body = req.body;
  try {
    const result = signInZodSchema.safeParse(body); // validate the body with zod schema we created
    if (!result.success) { // in case of an error validation return 400 bad request with message and error description
      return res.status(400).json({
        message: "Validation error",
        error: result.error.flatten().fieldErrors(),
      })
    }
    const { email, password } = result.data; // extract email and password
    const user = await User.findOne({ email }); // find user in the database
    if (!user) {
      return res.status(401).json({ message: "Invalid Credentials" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid Credentials" });
    }
    const token = jwt.sign({ sub: user._id }, secretKey, { expiresIn: "1h" });
    return res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
})

// add passport.authenticate('jwt', { session: false }) to protected routes to protect them
app.get("/protected", passport.authenticate('jwt', { session: false }), (req, res) => {
  return res.status(200).json({ message: "Protected route", user: req.user });
})


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
})