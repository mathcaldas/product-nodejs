const db = require('../config/database');
const bcrypt = require('node-php-password');

exports.registerUser = async (req, res) => {
    if(req.body.hasOwnProperty('novo_login') && req.body.hasOwnProperty('nova_senha') && req.body.hasOwnProperty('nome') && req.body.hasOwnProperty('email')) {
        
        const { novo_login, nova_senha, nome, email } = req.body;

        var token = bcrypt.hash(nova_senha);

        const hasUserQuery = await db.query(
            "SELECT login FROM usuarios WHERE login=$1",
            [novo_login]
        );

        if(hasUserQuery.rows.length === 0) {
            try {
                const insertUserQuery = await db.query(
                    "INSERT INTO usuarios (login, token, nome, email) VALUES ($1, $2, $3, $4)",
                    [novo_login, token, nome, email]
                );

                res.status(200).send(
                    {
                        sucesso : 1
                    }
                );
            }
            catch (err) {
                var errorMsg = "erro BD: ";
                res.status(200).send(
                    {
                        sucesso : 0,
                        cod_erro : 2,
                        erro : errorMsg.concat(err)
                    }
                );
            }
        }
        else {
            var errorMsg = "usuario ja cadastrado";
            res.status(200).send(
                {
                    sucesso : 0,
                    cod_erro : 1,
                    erro : errorMsg
                }
            );
        }
    }
    else {
        var errorMsg = "faltam parametros";
        res.status(200).send(
            {
                sucesso : 0,
                cod_erro : 3,
                erro : errorMsg
            }
        );
    }

};

exports.atualizarUsuario = async (req, res) => {

    const login = req.auth.user;
    const { novo_nome, novo_email } = req.body;
    
    if (!novo_nome && !novo_email) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }
    
    let campos = [];
    let valores = [];
    let indice = 1;
    
    if (novo_nome) {
        campos.push(`nome = $${indice}`);
        valores.push(novo_nome);
        indice++;
    }
    if (novo_email) {
        campos.push(`email = $${indice}`);
        valores.push(novo_email);
        indice++;
    }
    
    const query = `UPDATE usuarios SET ${campos.join(", ")} WHERE login = $${indice}`;
    valores.push(login);
    
    try {
        await db.query(query, valores);
        res.status(200).send({ sucesso: 1 });
    }
    catch (err) {
        res.status(200).send({
            sucesso: 0,
            cod_erro: 2,
            erro: "erro BD: " + err
        });
    }
};

exports.trocarSenha = async (req, res) => {

    const login = req.auth.user;

    if (!req.body.nova_senha) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }

    try {
        const novaSenha = req.body.nova_senha;
        const novoToken = bcrypt.hash(novaSenha);

        await db.query("UPDATE usuarios SET token = $1 WHERE login = $2", [novoToken, login]);
        res.status(200).send({ sucesso: 1 });

    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

exports.excluirUsuario = async (req, res) => {
    const login = req.auth.user;
    try {
        await db.query("DELETE FROM usuarios WHERE login = $1", [login]);
        res.status(200).send({ sucesso: 1 });
    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

exports.pegarDetalhesUsuario = async (req, res) => {
    if (!req.query.login) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }
    try {
        const result = await db.query("SELECT nome, email FROM usuarios WHERE login = $1", [req.query.login]);
        if (result.rows.length > 0) {
            const usuario = result.rows[0];
            res.status(200).send({
                sucesso: 1,
                nome: usuario.nome,
                email: usuario.email
            });
        } else {
            res.status(200).send({
                sucesso: 0,
                erro: "usuário não encontrado",
                cod_erro: 4
            });
        }
    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};