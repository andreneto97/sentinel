module.exports = {
  development: {
    client: "mysql2",
    connection: process.env.DATABASE_URL,
    migrations: { directory: "./migrations" },
  },
};
