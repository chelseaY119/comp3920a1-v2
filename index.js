require("./utils.js");

require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const saltRounds = 12;

const database = include("databaseConnection");
const db_utils = include("database/db_utils");
const db_users = include("database/users");
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3001;

const app = express();
const expireTime = 60 * 60 * 1000; // expire after one hour

/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_host = process.env.MONGODB_HOST;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  if (req.session.authenticated) {
    const username = req.session.username;
    res.send(`
  <h2>Hello, ${username}!</h2>
  <button onclick="window.location.href='/members'">Go to members area</button>
  <button onclick="window.location.href='/signout'">Sign out</button>
  `);
  } else {
    res.send(`
        <h2>Welcome! </h2>
        <button onclick="window.location.href='/createUser'">Sign Up</button>
        <button onclick="window.location.href='/login'">Login</button>
     
    
  `);
  }
});

app.get("/createTables", async (req, res) => {
  const create_tables = include("database/create_tables");

  var success = create_tables.createTables();
  if (success) {
    res.render("successMessage", { message: "Created tables." });
    //console.log("sucess!");
  } else {
    res.render("errorMessage", { error: "Failed to create tables." });
    //console.log("not sucess!");
  }
});

app.get("/createUser", (req, res) => {
  const errorMessage = req.query.error || "";
  console.log(errorMessage);
  res.render("createUser", { errorMessage });
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  if (!username && !password) {
    const errorMessage = "Please provide a username and a password.";
    return res.redirect(
      `/createUser?error=${encodeURIComponent(errorMessage)}`
    );
  } else if (!username) {
    const errorMessage = "Please provide a username.";
    return res.redirect(
      `/createUser?error=${encodeURIComponent(errorMessage)}`
    );
  } else if (!password) {
    const errorMessage = "Please provide a password.";
    return res.redirect(
      `/createUser?error=${encodeURIComponent(errorMessage)}`
    );
  } else if (!/^[a-zA-Z! '@#$%^&*()_+{}\[\]:;<>,.?~\\/-]+$/i.test(username)) {
    // Invalid input, handle the error appropriately
    res.status(400).send("Invalid username");
    return;
  }

  var hashedPassword = bcrypt.hashSync(password, saltRounds);

  var success = await db_users.createUser({
    user: username,
    hashedPassword: hashedPassword,
  });

  if (success) {
    var results = await db_users.getUsers();

    req.session.authenticated = true;
    req.session.username = username;
    res.redirect("/members");
  } else {
    res.render("errorMessage", { error: "Failed to create user." });
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  var results = await db_users.getUser({
    user: username,
    hashedPassword: password,
  });

  const query = "SELECT * FROM user WHERE username = ? AND password = ?";
  const [rows] = await database.query(query, [username, password]);

  if (rows.length >= 1) {
    res.send(rows);
  }

  if (results) {
    if (results.length == 1) {
      //there should only be 1 user in the db that matches
      if (bcrypt.compareSync(password, results[0].password)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect(`/members`);
        return;
      } else {
        console.log("invalid password");
      }
    } else {
      console.log(
        "invalid number of users matched: " + results.length + " (expected 1)."
      );
      res.redirect("/login");
      return;
    }
  }
  console.log("user not found ");
  //user and password combination not found
  res.redirect("/login");
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  res.render("loggedin");
});

function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

app.get("/members", (req, res) => {
  const username = req.session.username;
  const catid = getRandomNumber(1, 3);

  const imagePath = `/image/${catid}.png`;
  if (req.session.authenticated) {
    const username = req.session.username;
    res.send(`
  <h2>Hello, ${username}!</h2>
  <img src="${imagePath}" alt="Profile Image" width="300" height="400">
  <button onclick="window.location.href='/signout'">Sign out</button>
  `);
  } else {
    // Redirect to the login page if the user is not authenticated
    res.redirect("/");
  }
});

// app.get("/signout", (req, res) => {
//   // Clear session data
//   req.session.destroy((err) => {
//     if (err) {
//       console.error("Error destroying session:", err);
//       res.status(500).send("Internal Server Error");
//     } else {
//       // Redirect to the home page or login page after logout
//       res.redirect("/");
//     }
//   });
// });
app.get("/signout", (req, res) => {
  // Destroy the session in the database
  mongoStore.destroy(req.sessionID, (err) => {
    if (err) {
      console.error("Error destroying session in the database:", err);
      res.status(500).send("Internal Server Error");
    } else {
      // Clear session data from memory
      req.session.destroy(() => {
        // Redirect to the home page or login page after logout
        res.redirect("/");
      });
    }
  });
});

// these two at the end of the file
app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("<h1>404 page not found<h1>");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
