const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");

const server = express();

server.use(express.json());
server.use(cors());

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
        res.json({ message: "Congratulations on remembering your info!" });
      } else {
        res.status(400).json({ message: "invalid username or password" });
      }
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

// protect this route, only authenticated users should see it
server.get("/api/users", (req, res) => {
  db("users")
    .select("id", "username")
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log("\nrunning on port 3300\n"));
