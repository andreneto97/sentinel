exports.up = (knex) =>
  knex.schema.createTable("users", (table) => {
    table.increments("id");
    table.string("email").notNullable();
  });

exports.down = (knex) => knex.schema.dropTable("users");
