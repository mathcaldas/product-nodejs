const db = require('../config/database');
const { ImgurClient } = require('imgur');
const dotenv = require('dotenv');
const { createReadStream } = require('fs');

exports.getAllProducts = async (req, res) => {
    const { limit, offset, login } = req.query;
    if (!limit || !offset) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }

    try {
        let query, params;
        if (login) {
            query = "SELECT * FROM produtos WHERE usuarios_login = $1 LIMIT $2 OFFSET $3";
            params = [login, limit, offset];
        } else {
            query = "SELECT * FROM produtos LIMIT $1 OFFSET $2";
            params = [limit, offset];
        }
        const result = await db.query(query, params);
        res.status(200).send({
            sucesso: 1,
            produtos: result.rows
        });
    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

exports.addProduct = async (req, res) => {
    if('nome' in req.body && 'preco' in req.body && 'descricao' in req.body 
    && req.hasOwnProperty('file')) {
        const { nome, preco, descricao } = req.body;

        const imgurClient = new ImgurClient({ clientId: process.env.IMGUR_CLIENT_ID });
        const imgurRes = await imgurClient.upload(
            {
                image: createReadStream(req.file.path),
                type: 'stream'
            }
        );
        if(imgurRes.status === 200) {
            try {
                const addProductQuery = await db.query(
                    "INSERT INTO produtos(nome, preco, descricao, img, usuarios_login) VALUES($1, $2, $3, $4, $5)",
                    [nome, preco, descricao, imgurRes.data.link, req.auth.user]
                );
                res.status(200).send(
                    {
                        sucesso : 1
                    }
                );
            }
            catch(err) {
                var erroMsg = "erro BD: ";
                res.status(200).send(
                    {
                        sucesso : 0,
                        cod_erro : 2,
                        erro : erroMsg.concat(err)
                    }
                );
            }
        }
        else {
            res.status(200).send(
                {
                    sucesso : 0,
                    cod_erro : 2,
                    erro : "erro IMGUR: falha ao subir imagem para o IMGUR"
                }
            );
        }
    }
    else {
        var erroMsg = "faltam parametros";
		res.status(200).send(
			{
				sucesso : 0,
				cod_erro : 3,
				erro : erroMsg
			}
		);
    }
};

exports.pegarDetalhesProduto = async (req, res) => {
    if (!req.query.id) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }
    
    try {
        const result = await db.query(
            "SELECT nome, preco, descricao, usuarios_login AS criado_por, criado_em, img FROM produtos WHERE id = $1",
            [req.query.id]
        );
        if(result.rows.length > 0) {
            const produto = result.rows[0];
            res.status(200).send({
                sucesso: 1,
                nome: produto.nome,
                preco: produto.preco,
                descricao: produto.descricao,
                criado_por: produto.criado_por,
                criado_em: produto.criado_em,
                img: produto.img
            });
        } else {
            res.status(200).send({
                sucesso: 0,
                erro: "produto não encontrado",
                cod_erro: 4
            });
        }
    }
    catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

exports.atualizarProduto = async (req, res) => {
    // Verifica se o id foi enviado
    if (!req.body.id) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }

    const { id, novo_nome, novo_preco, nova_descricao } = req.body;
    // Verifica se ao menos um campo para atualização foi enviado (incluindo nova imagem via req.file)
    if (!novo_nome && !novo_preco && !nova_descricao && !req.hasOwnProperty('file')) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }

    try {
        // Consulta o produto para verificar se ele existe e se o usuário autenticado é o dono
        const productQuery = await db.query(
            "SELECT usuarios_login FROM produtos WHERE id = $1",
            [id]
        );

        if (productQuery.rows.length === 0) {
            return res.status(200).send({
                sucesso: 0,
                erro: "produto não encontrado",
                cod_erro: 4
            });
        }

        const produto = productQuery.rows[0];
        // Verifica se o usuário autenticado é o criador do produto
        if (produto.usuarios_login !== req.auth.user) {
            return res.status(200).send({
                sucesso: 0,
                erro: "usuario nao possui permissao",
                cod_erro: 0
            });
        }

        // Constrói dinamicamente os campos que serão atualizados
        let campos = [];
        let valores = [];
        let indice = 1;

        if (novo_nome) {
            campos.push(`nome = $${indice}`);
            valores.push(novo_nome);
            indice++;
        }
        if (novo_preco) {
            campos.push(`preco = $${indice}`);
            valores.push(novo_preco);
            indice++;
        }
        if (nova_descricao) {
            campos.push(`descricao = $${indice}`);
            valores.push(nova_descricao);
            indice++;
        }
        // Se uma nova imagem foi enviada
        if (req.hasOwnProperty('file')) {
            const { ImgurClient } = require('imgur');
            const { createReadStream } = require('fs');
            const imgurClient = new ImgurClient({ clientId: process.env.IMGUR_CLIENT_ID });
            const imgurRes = await imgurClient.upload({
                image: createReadStream(req.file.path),
                type: 'stream'
            });

            if (imgurRes.status === 200) {
                campos.push(`img = $${indice}`);
                valores.push(imgurRes.data.link);
                indice++;
            } else {
                return res.status(200).send({
                    sucesso: 0,
                    erro: "erro IMGUR: falha ao subir imagem para o IMGUR",
                    cod_erro: 2
                });
            }
        }

        // Monta a query de atualização – já que já verificamos o dono, atualizamos pelo id
        const query = `UPDATE produtos SET ${campos.join(", ")} WHERE id = $${indice} AND usuarios_login = $${indice + 1}`;
        valores.push(id, req.auth.user);

        await db.query(query, valores);
        res.status(200).send({ sucesso: 1 });
    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

exports.excluirProduto = async (req, res) => {
    // Verifica se o id foi enviado
    if (!req.body.id) {
        return res.status(200).send({
            sucesso: 0,
            erro: "faltam parametros",
            cod_erro: 3
        });
    }

    const { id } = req.body;
    try {
        // Consulta o produto para verificar se ele existe e se o usuário autenticado é o dono
        const productQuery = await db.query(
            "SELECT usuarios_login FROM produtos WHERE id = $1",
            [id]
        );

        if (productQuery.rows.length === 0) {
            return res.status(200).send({
                sucesso: 0,
                erro: "produto não encontrado",
                cod_erro: 4
            });
        }

        const produto = productQuery.rows[0];
        // Verifica se o usuário autenticado é o criador do produto
        if (produto.usuarios_login !== req.auth.user) {
            return res.status(200).send({
                sucesso: 0,
                erro: "usuario nao possui permissao",
                cod_erro: 0
            });
        }

        // Remove o produto
        await db.query(
            "DELETE FROM produtos WHERE id = $1 AND usuarios_login = $2",
            [id, req.auth.user]
        );
        res.status(200).send({ sucesso: 1 });
    } catch (err) {
        res.status(200).send({
            sucesso: 0,
            erro: "erro BD: " + err,
            cod_erro: 2
        });
    }
};

