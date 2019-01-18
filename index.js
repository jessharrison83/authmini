const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const db = require("./database/dbConfig.js");

const server = express();

//custom middleware
const protect = (req, res, next) => {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).send("access denied");
  }
};

server.use(express.json());
server.use(cors());
server.use(
  session({
    name: "notsession", // default is connect.sid
    secret: "nobody tosses a dwarf!",
    cookie: {
      maxAge: 1 * 24 * 60 * 60 * 1000
    }, // 1 day in milliseconds
    httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
    resave: false,
    saveUninitialized: false
  })
);

server.get("/", (req, res) => {
  res.send("Its Alive!");
});

server.post("/api/register", (req, res) => {
  const newUser = req.body;
  newUser.password = bcrypt.hashSync(newUser.password);
  db("users")
    .insert(newUser)
    .then(id => {
      res.send({ message: `id ${id} created` });
    })
    .catch(err => {
      res.status(500).send(err);
    });
});

server.post("/api/login", (req, res) => {
  const user = req.body;
  db("users")
    .where("username", user.username)
    .then(users => {
      if (
        users.length &&
        bcrypt.compareSync(user.password, users[0].password)
      ) {
        req.session.userId = users[0].id;
        res.json({ message: "Congratulations on remembering your info!" });
      } else {
        res.status(400).json({ message: "invalid username or password" });
      }
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

server.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      res.status(500).json(err);
    } else {
      res.status(200).json({ message: "logout successful" });
    }
  });
});

// protect this route, only authenticated users should see it
server.get("/api/users", protect, (req, res) => {
  db("users")
    .select("id", "username")
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log("\nrunning on port 3300\n"));
