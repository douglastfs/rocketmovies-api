const AppError = require("../utils/AppError");
const knex = require("../database/knex");
const { hash, compare } = require("bcryptjs");
const validateEmail = require("../utils/validateEmail");

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body;

    const [ checkUserExists ] = await knex("users")
    .whereRaw("email = ? COLLATE NOCASE", [email]);

    console.log(checkUserExists);

    if(!name)
      throw new AppError("O nome é obrigatório");

    if(!password)
      throw new AppError("A senha é obrigatória");

    if(!validateEmail(email))
      throw new AppError("Digite um E-mail válido");

    if(checkUserExists)
      throw new AppError("Este E-mail já está cadastrado.")


    const hashedPassword = await hash(password, 8)

    await knex("users").insert({
      name,
      email,
      password: hashedPassword
    });

    return response.status(201).json();
  };

  async update(request, response) {
    const { name, email, password, old_password } = request.body;
    const id = request.user.id;

    const [ user ] = await knex("users").where({ id });
    const [ userWithUpdatedEmail ] = await knex("users")
    .whereRaw("email = ? COLLATE NOCASE", [email]);

    if(!user)
      throw new AppError("Usuário não encontrado");

    if(userWithUpdatedEmail && userWithUpdatedEmail.id != user.id)
      throw new AppError("Este e-mail pertence a outro usuário.");

    if(!validateEmail(email))
      throw new AppError("Digite um E-mail válido");

    if(password && !old_password)
      throw new AppError("Para mudar a senha precisa inserir a senha antiga.");

    if(password && old_password){
      const checkOldPassowrd = await compare(old_password, user.password);
      if(!checkOldPassowrd)
        throw new AppError("A senha não confere.")
      user.password = await hash(password, 8);
    }


    await knex("users").where({ id }).update({
      name: name,
      email: email,
      password: user.password,
      updated_at: knex.fn.now()
    });

    return response.json();
  };

  async delete(request, response) {
    const { id } = request.params;

    await knex("users").where({id}).delete();

    return response.json();
  }
};

module.exports = UsersController;
