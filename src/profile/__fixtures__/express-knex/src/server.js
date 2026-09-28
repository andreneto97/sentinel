const express = require("express");
const session = require("express-session");
const users = require("./routes/users");

const app = express();

app.use(session({ secret: process.env.SESSION_SECRET }));
app.use("/api", users);

app.listen(process.env.PORT || 3000);
