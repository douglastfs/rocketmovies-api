exports.up = knex => knex.schema.createTable("tags", table => {
  table.increments("id").primary();
  table.text("name").notNullable();

  table.integer("user_id").references("id").inTable("users").onDelete("CASCADE");
  table.integer("note_id").references("id").inTable("notes").onDelete("CASCADE");
});

exports.down = knex => knex.schema.dropTable("tags");