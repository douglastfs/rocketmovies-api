const knex= require("../database/knex");
const AppError = require("../utils/AppError");

class NotesController {
  async create( request, response ) {
    const { title, description, rating, tags} = request.body;
    const user_id = request.user.id;

    if(rating < 1 || rating > 5)
      throw new AppError("A nota precisa ser de 1 a 5");

    const [ note_id ] = await knex("notes").insert({
      title,
      description,
      rating,
      user_id
    });

    const TagsInsert = tags.map( tag => {
      return {
        note_id,
        user_id,
        name: tag
      }
    });

    await knex("tags").insert(TagsInsert);

    return response.json();
  }

  async show( request, response ) {
    const { id } = request.params;

    const [ note ] = await knex("notes").where({ id });
    const tags = await knex("tags").where({ note_id: id }).orderBy("id");

    return response.json({
      ...note,
      tags
    });
  }

  async delete( request, response ) {
    const { id } = request.params;

    await knex("notes").where({ id }).delete();

    return response.json();
  }

  async index( request, response ) {
    const { title, tags, rating } = request.query;
    const user_id = request.user.id;

    let notes;

    if(tags) {
      const filterTags = tags.split(',').map(tag => tag.trim());
      notes = await knex("tags")
        .select([
          "notes.id",
          "notes.user_id",
          "notes.title",
          "notes.description",
          "notes.rating",
        ])
        .where("notes.user_id", user_id)
        .whereLike("notes.title", `%${title}%`)
        .whereIn(knex.raw("LOWER(name)"), filterTags.map(tag => tag.toLowerCase()))
        .innerJoin("notes", "notes.id", "tags.note_id")
        .orderBy("notes.title");
    } else if(rating) {
      notes = await knex("notes")
      .where({  user_id })
      .andWhere("rating", rating);
    } else {
      notes = await knex("notes")
        .where({ user_id })
        .whereLike("title", `%${title}%`)
        .orderBy("title");
    }

    const userTags = await knex("tags").where({ user_id });
    const noteWithTags = notes.map(note => {
      const noteTags = userTags.filter(tag => tag.note_id === note.id);
      return {
        ...note,
        tags: noteTags
      }
    });

    return response.json(noteWithTags);
  }
};

module.exports = NotesController;
