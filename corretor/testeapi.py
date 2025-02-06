import requests
import psycopg
import base64
import bcrypt
import hashlib
import json
import string
import random

errors = 0

# Configurações de conexão com o banco de dados
DB_CONFIG = {
    "dbname": "productifes",
    "user": "avnadmin",
    "password": "AVNS_BUR3AJuWsgm2Y6ipXBB",
    "host": "pg-32571217-dispmoveisbsi-a778.d.aivencloud.com",
    "port": "17551"
}

# URL base da sua API
API_BASE_URL = "http://localhost:3000/api/"

# Função para conectar ao banco de dados
def connect_db():
    conn = psycopg.connect(**DB_CONFIG)
    return conn

# Função para verificar se um usuário existe no banco
def check_user_in_db(login):
    try:
        # Estabelece a conexão e gerencia o cursor com o 'with'
        with connect_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT login, nome, email, token FROM public.usuarios WHERE login = %s;", (login,))
                user = cursor.fetchone()  # Recupera o primeiro usuário correspondente ao login

                return user if user else None
    except psycopg.Error as error:
        return None
    except Exception as error:
        return None


def generate_php_compatible_hash(password: str, cost: int = 10) -> str:
    """
    Gera um hash de senha compatível com o formato do password_hash do PHP.

    Args:
        password (str): A senha a ser hasheada.
        cost (int): O custo do algoritmo (número de iterações). O padrão do PHP é 10.

    Returns:
        str: Hash no formato compatível com PHP.
    """
    # Gera o hash usando bcrypt (com prefixo padrão $2b)
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Substitui manualmente o prefixo $2b por $2y (compatibilidade com PHP)
    php_compatible_hash = hashed.decode('utf-8').replace("$2b$", "$2y$")

    return php_compatible_hash

def generate_randon_login():
    # using random.choices()
    # generating random strings
    return ''.join(random.choices(string.ascii_lowercase, k=7))

# Função para inserir um usuário existe no banco
def insert_user_in_db(login, senha, nome, email):
    try:
        # Gerar o token (hash da senha)
        token = generate_php_compatible_hash(senha)

        # Gerenciamento da conexão e do cursor com 'with'
        with connect_db() as conn:
            with conn.cursor() as cursor:
                # Corrigir a query SQL
                cursor.execute("""
                    INSERT INTO public.usuarios (login, token, nome, email) 
                    VALUES (%s, %s, %s, %s);
                """, (login, token, nome, email))

                # Commit da transação
                conn.commit()

                # Verificar se a inserção foi bem-sucedida
                if cursor.rowcount > 0:  # Se a inserção afetou pelo menos uma linha
                    return True
                else:
                    return False

    except psycopg.DatabaseError as error:
        return False
    except Exception as error:
        return False

# Função para excluir um usuário existe no banco
def delete_user_in_db(login):
    try:
        # Verificar se o usuário existe
        user = check_user_in_db(login)
        if user is not None:
            # Usar 'with' para gerenciar automaticamente a conexão e o cursor
            with connect_db() as conn:
                with conn.cursor() as cursor:
                    # Executar o comando DELETE
                    cursor.execute("DELETE FROM public.usuarios WHERE login = %s;", (login,))

                    # Commit da transação
                    conn.commit()

                    # Verificar se a exclusão foi bem-sucedida (afetar pelo menos uma linha)
                    if cursor.rowcount > 0:
                        return True
                    else:
                        return False
        else:
            return False

    except psycopg.Error as error:
        return False
    except Exception as error:
        return False

# Função para verificar se um produto existe no banco
def check_product_in_db(product_id):
    try:
        # Usar 'with' para gerenciar automaticamente a conexão e o cursor
        with connect_db() as conn:
            with conn.cursor() as cursor:
                # Executar a consulta para encontrar o produto pelo id
                cursor.execute("SELECT * FROM public.produtos WHERE id = %s;", (product_id,))
                product = cursor.fetchone()  # Retorna o primeiro produto encontrado ou None

                return product  # Retorna o produto, ou None se não encontrado

    except psycopg.Error as error:
        return None
    except Exception as error:
        return None

# Função para inserir um produto no banco
def insert_product_in_db(nome, preco, descricao, login):
    try:
        img = ""  # Valor padrão para a imagem (caso não seja fornecida)

        # Usar 'with' para gerenciar automaticamente a conexão e o cursor
        with connect_db() as conn:
            with conn.cursor() as cursor:
                # Inserir o produto e retornar o ID gerado
                cursor.execute("""
                    INSERT INTO public.produtos (nome, preco, descricao, img, usuarios_login)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (nome, preco, descricao, img, login))

                # Obter o ID do produto inserido
                product_id = cursor.fetchone()[0]

                # Commit da transação
                conn.commit()

        return product_id

    except psycopg.Error as error:
        return None
    except Exception as error:
        return None

# Função para excluir um produto no banco
def delete_product_in_db(product_id):
    try:
        # Verificar se o produto existe
        product = check_product_in_db(product_id)
        if product is not None:
            # Usar 'with' para gerenciar automaticamente a conexão e o cursor
            with connect_db() as conn:
                with conn.cursor() as cursor:
                    # Executar o comando DELETE
                    cursor.execute("DELETE FROM public.produtos WHERE id = %s;", (product_id,))

                    # Commit da transação
                    conn.commit()

                    # Verificar se a exclusão foi bem-sucedida
                    if cursor.rowcount > 0:
                        return True
                    else:
                        return False
        else:
            return False

    except psycopg.Error as error:
        return False
    except Exception as error:
        return False

# Função para realizar a requisição e validar a resposta
def test_api_call(endpoint, method="POST", data=None, auth=None, files=None):
    url = f"{API_BASE_URL}/{endpoint}"

    headers = {}
    if auth:
        # Se a autenticação for necessária, envia o cabeçalho de Basic Auth
        headers['Authorization'] = auth

    try:
        if method == "POST":
            if files:
                # Se for necessário enviar arquivos, usamos o parâmetro files
                return requests.post(url, data=data, files=files, headers=headers)
            else:
                return requests.post(url, data=data, headers=headers)
        elif method == "GET":
            return requests.get(url, params=data, headers=headers)

    except requests.exceptions.RequestException as e:
        print(f"Erro de requisição: {e}")
        return None

# Função para gerar o cabeçalho de Basic Auth a partir do login e senha
def basic_auth_header(login, senha):
    if not login or not senha:
        raise ValueError("Login e senha não podem ser vazios.")
    # Codificando login e senha para base64 no formato "login:senha"
    auth_value = base64.b64encode(f"{login}:{senha}".encode('utf-8')).decode('utf-8')
    return f"Basic {auth_value}"

# Função para verificar se a senha simples corresponde ao hash da senha
def verify_password(plain_password, hashed_password):
    # Verifica se a senha simples corresponde ao hash da senha
    if not plain_password or not hashed_password:
        raise ValueError("Senha simples e hash não podem ser vazios.")
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def verify_api_response(response, expected_success, expected_error_code=None):
    """Função auxiliar para verificar a resposta da API e retornar mensagens de erro."""
    error_msg = ""

    try:
        # Tenta parsear o JSON da resposta
        content = response.content.decode('utf-8-sig')  # 'utf-8-sig' remove o BOM automaticamente
        response_data = json.loads(content)

        # Verifica se as chaves essenciais estão presentes na resposta
        if "sucesso" not in response_data:
            error_msg = "Erro: A resposta não contém a chave 'sucesso'."
        elif response_data.get("sucesso") != expected_success:
            error_msg = f"Resposta incompatível com o esperado. Esperado: sucesso {expected_success}. Retornado: sucesso {response_data.get('sucesso')}"

        if expected_error_code is not None:
            if "cod_erro" not in response_data:
                error_msg = "Erro: A resposta não contém a chave 'cod_erro'."
            elif response_data.get("cod_erro") != expected_error_code:
                error_msg = f"Resposta incompatível com o esperado. Esperado: cod_erro {expected_error_code}. Retornado: cod_erro {response_data.get('cod_erro')}"

    except ValueError:
        # Verifica o código HTTP da resposta
        if response.status_code != 200:
            error_msg = f"Ponto de acesso de API retornou código HTTP {response.status_code}. Resposta: {response.text}"
        else:
            error_msg = f"Erro ao tentar parsear a resposta JSON da API. Resposta: {response.text}"




    return error_msg

def hash_image(file_path):
    """Calcula o hash de uma imagem a partir do caminho do arquivo"""
    hash_sha256 = hashlib.sha256()  # Escolhendo SHA-256 para calcular o hash da imagem
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def compare_images(local_image_path, image_url):
    """Compara a imagem local com a imagem da URL"""

    # Verifica se o URL não está vazio
    if not image_url:
        return "O campo img do produto está vazio. Possível erro na hora do upload para o Imgur."

    # Calcular o hash da imagem local
    local_image_hash = hash_image(local_image_path)
    print(f"Hash da imagem local: {local_image_hash}")

    # Baixar a imagem da URL
    response = requests.get(image_url)
    if response.status_code != 200:
        return "Erro: Falha ao baixar a imagem do Imgur."

    # Calcular o hash da imagem da URL
    url_image_hash = hashlib.sha256(response.content).hexdigest()

    # Comparar os hashes das duas imagens
    if local_image_hash == url_image_hash:
        return ""  # Imagens são iguais, retorna mensagem vazia
    else:
        return "Erro: A imagem presente no produto é diferente da imagem que foi usada para atualizar o produto"

# 3 erros possíveis
def test_registrar_usuario():
    print("====================================")
    print("registrar")

    global errors
    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # para ter certeza de que o usuário já não existe
    delete_user_in_db(login)

    print("Teste: verificação de parâmetros")
    data = {
        'novo_login': login,
        'nova_senha': senha,
        'nome': nome,
    }

    # Verifica o caso de erro ao fornecer dados incompletos
    response = test_api_call("registrar", "POST", data)
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    # Testar o registro de um usuário com dados corretos
    print("Teste: registro de usuário com sucesso")
    data['email'] = email  # Adicionando o campo de email

    response = test_api_call("registrar", "POST", data)
    error_msg = verify_api_response(response, expected_success=1)

    if not error_msg:
        # Verifica se o usuário foi registrado corretamente no banco
        user = check_user_in_db(login)
        if user is None:
            error_msg = "Usuário registrado não foi encontrado no banco de dados."
        elif user[1] != nome or user[2] != email:
            error_msg = f"Campos do usuário retornado não batem com os registrados. Nome esperado: {nome}, Email esperado: {email}. Retornados: {user[1]}, {user[2]}"

    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    # Teste de tentativa de registro de um usuário duplicado
    print("Teste: registro de usuário em duplicidade")

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    response = test_api_call("registrar", "POST", data)
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=1)

    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    print("\n")

    # Ao final, excluir o usuário recém-registrado
    delete_user_in_db(login)

# 5 erros possíveis
def test_atualizar_usuario():
    print("====================================")
    print("atualizar_usuario")

    global errors
    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'
    
    senha_errada = 'senhaerrada'


    # Insere usuários diretamente no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tenar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.\n")
            return

    novo_nome = 'Daniel de Souza'
    novo_email = 'daniel.souza@example.com'
    novo_nome_depois = 'Daniel de Assis'

    # Teste verificação de parâmetros (sem dados)
    print("Teste: verificação de parâmetros")
    response = test_api_call("atualizar_usuario", "POST", auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)
    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    # Teste de atualização com dados corretos
    print("Teste: verificação de autenticação")

    data = {'novo_nome': novo_nome, 'novo_email': novo_email}

    response = test_api_call("atualizar_usuario", "POST", data=data, auth=basic_auth_header(login, senha_errada))
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=0)
    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    # Teste de atualização completa
    print("Teste: atualização completa")
    response = test_api_call("atualizar_usuario", "POST", data=data, auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=1)
    if not error_msg:
        user = check_user_in_db(login)
        if user is None:
            error_msg = "Usuário não foi encontrado no BD."
        elif user[1] != novo_nome or user[2] != novo_email:
            error_msg = f"Campos do usuário não batem com o atualizado. Esperado: {novo_nome}, {novo_email}. Retornado: {user[1]}, {user[2]}"

    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    # Teste de atualização parcial (apenas nome)
    print("Teste: atualização parcial")
    data = {'novo_nome': novo_nome_depois}
    response = test_api_call("atualizar_usuario", "POST", data=data, auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=1)
    if not error_msg:
        user = check_user_in_db(login)
        if user is None:
            error_msg = "Usuário não foi encontrado no BD."
        elif user[1] != novo_nome_depois:
            error_msg = f"Campo nome não atualizado corretamente. Esperado: {novo_nome_depois}. Retornado: {user[1]}"

    if error_msg:
        errors += 1
        print(error_msg)
    else:
        print("OK")

    print("\n")
    # Ao final, excluir os usuários
    delete_user_in_db(login)

# 4 erros possíveis
def test_trocar_senha():
    print("====================================")
    print("trocar_senha")

    global errors  # Contador de erros

    # Dados dos usuários
    users = [
        {'login': generate_randon_login(), 'senha': 'senha123', 'nome': 'Daniel Ribeiro Trindade', 'email': 'daniel@example.com'},
        {'login': generate_randon_login(), 'senha': 'senha123', 'nome': 'Daniel Ribeiro Trindade', 'email': 'daniel@example.com'}
    ]

    nova_senha = '123456'
    
    senha_errada = 'senha_errada'

    # Inserindo usuários no BD
    for user in users:
        if not check_user_in_db(user['login']):
            if not insert_user_in_db(user['login'], user['senha'], user['nome'], user['email']):
                print("Ocorreu um erro ao tenar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
                return

    try:
        print("Teste: verificação de parâmetros")
        response = test_api_call("trocar_senha", "POST", auth=basic_auth_header(users[0]['login'], users[0]['senha']))
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)
        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("Teste: verificação de autenticação")
        data = {'nova_senha': nova_senha}
        response = test_api_call("atualizar_usuario", "POST", data=data, auth=basic_auth_header(users[0]['login'], senha_errada))
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=0)
        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("Teste: troca de senha com sucesso")
        response = test_api_call(
            "trocar_senha",
            "POST",
            data=data,
            auth=basic_auth_header(users[0]['login'], users[0]['senha'])
        )
        error_msg = verify_api_response(response, expected_success=1)
        if not error_msg:
            user = check_user_in_db(users[0]['login'])
            if user is None:
                error_msg = "Erro: Usuário não encontrado no BD"
            elif not verify_password(nova_senha, user[3]):
                error_msg = "Erro: A senha não foi trocada no BD"

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("\n")

    finally:
        # Limpando usuários do BD
        for user in users:
            delete_user_in_db(user['login'])

# 2 erros possíveis
def test_excluir_usuario():
    print("====================================")
    print("excluir_usuario")

    global errors  # Contador de erros

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'
    
    senha_errada = 'senha_errada'

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    try:
        print("Teste: verificação de autenticação")

        # Teste sem autenticação
        response = test_api_call("excluir_usuario", "POST", auth=basic_auth_header(login, senha_errada))
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=0)
        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("Teste: exclusão de usuário com sucesso")

        # Teste com autenticação válida
        response = test_api_call("excluir_usuario", "POST", auth=basic_auth_header(login, senha))
        error_msg = verify_api_response(response, expected_success=1)
        if not error_msg:
            # Verifica se o usuário foi excluído
            user = check_user_in_db(login)
            if user is not None:
                error_msg = "Erro: Usuário não foi excluído do BD"

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("\n")

    finally:
        # Limpeza do banco de dados
        delete_user_in_db(login)

# 2 erros possíveis
def test_pegar_detalhes_usuario():
    print("====================================")
    print("pegar_detalhes_usuario")

    global errors  # Contador de erros

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print(
                "Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    try:
        print("Teste: verificação de parâmetros")

        # Teste sem parâmetros
        response = test_api_call("pegar_detalhes_usuario", "GET")
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("Teste: pegar detalhes do usuário")

        # Teste com parâmetros válidos
        data = {'login': login}
        response = test_api_call("pegar_detalhes_usuario", "GET", data=data)
        error_msg = verify_api_response(response, expected_success=1)
        if not error_msg:  # Caso a resposta inicial seja bem-sucedida
            try:
                content = response.content.decode('utf-8-sig')  # 'utf-8-sig' remove o BOM automaticamente
                response_data = json.loads(content)

                # Verifica se as chaves essenciais estão presentes na resposta
                if not all(key in response_data for key in ["sucesso", "nome", "email"]):
                    error_msg = "Erro: a resposta da API não contém as chaves esperadas ('sucesso', 'nome', 'email')."
                else:
                    # Verifica se o usuário existe no BD
                    user = check_user_in_db(login)
                    if not user:
                        error_msg = "Usuário não foi encontrado no BD."
                    elif user[1] != response_data["nome"] or user[2] != response_data["email"]:
                        error_msg = "Os campos do usuário retornados não coincidem com os armazenados no BD."

            except ValueError:
                error_msg = f"Erro ao tentar parsear a resposta JSON da API. Resposta: {response.text}"

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("\n")

    finally:
        # Limpeza do banco de dados
        delete_user_in_db(login)

# 2 erros possíveis
def test_pegar_detalhes_produto():
    print("====================================")
    print("pegar_detalhes_produto")

    global errors  # Contador de erros

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    # Dados do produto
    nome_produto = 'pudim'
    preco_produto = '100'
    descricao_produto = 'pudim teste'

    # Inserção do produto no BD
    product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)

    try:
        # Teste: verificação de parâmetros
        print("Teste: verificação de parâmetros")
        response = test_api_call("pegar_detalhes_produto", "GET")
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        # Teste: pegar detalhes do produto
        print("Teste: pegar detalhes do produto")
        data = {'id': product_id}
        response = test_api_call("pegar_detalhes_produto", "GET", data=data)
        error_msg = verify_api_response(response, expected_success=1)

        if not error_msg:
            try:
                content = response.content.decode('utf-8-sig')  # 'utf-8-sig' remove o BOM automaticamente
                response_data = json.loads(content)

                # Verifica se a resposta contém todas as chaves necessárias
                required_keys = {"nome", "preco", "descricao", "criado_por", "criado_em", "img"}
                if not required_keys.issubset(response_data.keys()):
                    error_msg = "A resposta não possui todos os campos necessários."
                else:
                    # Verifica se os dados do produto retornados batem com os dados do banco de dados
                    product = check_product_in_db(product_id)
                    if not product:
                        error_msg = "Produto não foi encontrado no BD."
                    elif not (product[1] == response_data["nome"] and
                              str(product[2]) == response_data["preco"] and
                              product[3] == response_data["descricao"]):
                        error_msg = "Campos do produto retornado não batem com os dados do BD."

            except ValueError:
                error_msg = f"Erro ao tentar parsear a resposta JSON da API. Resposta: {response.text}"

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("\n")

    finally:
        # Limpeza do banco de dados
        delete_product_in_db(product_id)
        delete_user_in_db(login)

# 4 erros possíveis
def test_excluir_produto():
    print("====================================")
    print("excluir_produto")

    global errors  # Contador de erros

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # Dados do usuário 2
    login2 = generate_randon_login()
    senha2 = 'senha123'
    nome2 = 'Daniel Ribeiro Trindade'
    email2 = 'daniel@example.com'
    
    senha_errada = 'senha_errada'

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    if not check_user_in_db(login2):
        if not insert_user_in_db(login2, senha2, nome2, email2):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    # Dados do produto
    nome_produto = 'pudim'
    preco_produto = '100'
    descricao_produto = 'pudim teste'

    # Inserção do produto no BD
    product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
    if not product_id:
        print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
        return

    try:
        # Teste: verificação de parâmetros
        print("Teste: verificação de parâmetros")
        response = test_api_call("excluir_produto", "POST", auth=basic_auth_header(login, senha))
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        # Teste: verificação de autenticação
        print("Teste: verificação de autenticação")
        if check_product_in_db(product_id) is None:
            product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
            if not product_id:
                print(
                    "Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
                return

        data = {'id': product_id}
        response = test_api_call("excluir_produto", "POST", data=data, auth=basic_auth_header(login, senha_errada))
        error_msg = verify_api_response(response, expected_success=0, expected_error_code=0)

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        # Teste: verificação de permissão para operação
        print("Teste: verificação de permissão para operação")

        if check_product_in_db(product_id) is None:
            product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
            if not product_id:
                print(
                    "Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
                return

        response = test_api_call("excluir_produto", "POST", data=data, auth=basic_auth_header(login2, senha2))
        error_msg = verify_api_response(response, expected_success=0)

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        # Teste: exclusão do produto com sucesso
        print("Teste: exclusão de produto com sucesso")
        if check_product_in_db(product_id) is None:
            product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
            if not product_id:
                print(
                    "Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
                return

        data = {'id': product_id}
        response = test_api_call("excluir_produto", "POST", data=data, auth=basic_auth_header(login, senha))
        error_msg = verify_api_response(response, expected_success=1)

        if not  error_msg:
            product = check_product_in_db(product_id)
            if product is not None:
                error_msg = "Produto foi encontrado no BD, mas não deveria."

        if error_msg:
            print(error_msg)
            errors += 1
        else:
            print("OK")

        print("\n")
    finally:
        # Limpeza do banco de dados
        delete_product_in_db(product_id)
        delete_user_in_db(login)
        delete_user_in_db(login2)

# 5 erros possíveis
def test_atualizar_produto():
    print("====================================")
    print("atualizar_produto")

    global errors  # Contador de erros

    path_product_img = "pudim.jpg"

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # Dados do usuário 2
    login2 = generate_randon_login()
    senha2 = 'senha123'
    nome2 = 'Daniel Ribeiro Trindade'
    email2 = 'daniel@example.com'
    
    senha_errada = 'senha_errada'

    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return
    if not check_user_in_db(login2):
        if not insert_user_in_db(login2, senha2, nome2, email2):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    # Dados do produto
    nome_produto = 'pudim'
    preco_produto = '100'
    descricao_produto = 'pudim teste'

    # Inserção do produto no BD
    product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
    if not product_id:
        print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
        return

    # Dados para atualização
    novo_nome_produto = 'pudim atualizado'
    novo_preco_produto = '150.00'
    nova_descricao_produto = 'pudim teste atualizado'
    files = {'nova_img': open(path_product_img, 'rb')}

    novo_nome_produto2 = 'pudim atualizado 2'
    novo_preco_produto2 = '155.00'

    # Teste: verificação de parâmetros
    print("Teste: verificação de parâmetros")
    response = test_api_call("atualizar_produto", "POST", auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    # Teste: verificação de autenticação
    print("Teste: verificação de autenticação")
    data = {
        'id': product_id,
        'novo_nome': novo_nome_produto,
        'novo_preco': novo_preco_produto,
        'nova_descricao': nova_descricao_produto,
    }
    response = test_api_call("atualizar_produto", "POST", data=data, files=files, auth=basic_auth_header(login, senha_errada))
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=0)

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    # Teste: verificação de permissão para operação
    print("Teste: verificação de permissão para operação\n")
    response = test_api_call("atualizar_produto", "POST", data=data, files=files, auth=basic_auth_header(login2, senha2))
    error_msg = verify_api_response(response, expected_success=0)

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    # Teste: atualização completa
    print("Teste: atualização completa")
    response = test_api_call("atualizar_produto", "POST", data=data, files=files, auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=1)

    if not error_msg:
        product = check_product_in_db(product_id)
        if product is None:
            error_msg = "Produto não foi encontrado no BD"
        elif product[1] != novo_nome_produto or str(product[2]) != novo_preco_produto or product[3] != nova_descricao_produto:
            error_msg = "Campos do produto retornado não batem com o atualizado"
        else:
            error_msg = compare_images(path_product_img, product[4])

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    # Teste: atualização parcial
    print("Teste: atualização parcial")
    data = {
        'id': product_id,
        'novo_nome': novo_nome_produto2,
        'novo_preco': novo_preco_produto2,
    }
    response = test_api_call("atualizar_produto", "POST", data=data, auth=basic_auth_header(login, senha))
    error_msg = verify_api_response(response, expected_success=1)

    if not error_msg:
        product = check_product_in_db(product_id)
        if product is None:
            error_msg = "Produto não foi encontrado no BD"
        elif product[1] != novo_nome_produto2 or str(product[2]) != novo_preco_produto2:
            error_msg = "Campos do produto retornado não batem com a atualização parcial"

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    print("\n")

    # Limpeza do banco de dados
    delete_user_in_db(login)
    delete_user_in_db(login2)
    delete_product_in_db(product_id)

# 2 erros possíveis
def test_pegar_produtos():
    print("====================================")
    print("pegar_produtos")

    global errors  # Contador de erros

    # Dados do usuário
    login = generate_randon_login()
    senha = 'senha123'
    nome = 'Daniel Ribeiro Trindade'
    email = 'daniel@example.com'

    # Inserção direta no BD
    # Inserção direta no BD
    if not check_user_in_db(login):
        if not insert_user_in_db(login, senha, nome, email):
            print("Ocorreu um erro ao tentar acessar o BD diretamente. Verifique os dados de conexão com o BD. A correção não pode prosseguir para o ponto de acesso.")
            return

    # Dados do produto
    nome_produto = 'pudim'
    preco_produto = '100'
    descricao_produto = 'pudim teste'

    # Inserção de produtos no BD
    product_id = insert_product_in_db(nome_produto, preco_produto, descricao_produto, login)
    product_id1 = insert_product_in_db('pudim1', '1001', 'pudim teste1', login)
    product_id2 = insert_product_in_db('pudim2', '1002', 'pudim teste2', login)
    product_id3 = insert_product_in_db('pudim3', '1003', 'pudim teste3', login)

    # Teste: verificação de parâmetros
    print("Teste: verificação de parâmetros")
    response = test_api_call("pegar_produtos", "GET")
    error_msg = verify_api_response(response, expected_success=0, expected_error_code=3)

    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    # Teste: pegar produtos
    print("Teste: pegar produtos com sucesso")
    data = {
        'limit': 10,
        'offset': 0,
        'login': login,
    }

    response = test_api_call("pegar_produtos", "GET", data=data)
    error_msg = verify_api_response(response, expected_success=1)

    if not error_msg:
        try:
            content = response.content.decode('utf-8-sig')  # 'utf-8-sig' remove o BOM automaticamente
            response_data = json.loads(content)

            required_keys = {"sucesso", "produtos"}
            if not required_keys.issubset(response_data.keys()):
                error_msg = "A resposta não possui todos os campos necessários"
            else:
                products = response_data.get("produtos")
                for product in products:
                    required_product_keys = {"id", "nome", "preco", "img"}
                    if not required_product_keys.issubset(product.keys()):
                        error_msg = "Produto retornado não possui todos os campos necessários"
                    else:
                        product_bd = check_product_in_db(product['id'])
                        if not product_bd:
                            error_msg = "Produto não encontrado no BD"
                        elif product_bd[5] != login:
                            error_msg = "Os produtos retornados não são apenas do login que os criou"
        except ValueError:
            error_msg = "Erro: a resposta da API não pôde ser convertida para JSON."


    if error_msg:
        print(error_msg)
        errors += 1
    else:
        print("OK")

    print("\n")

    # Limpeza do banco de dados
    delete_product_in_db(product_id)
    delete_product_in_db(product_id1)
    delete_product_in_db(product_id2)
    delete_product_in_db(product_id3)
    delete_user_in_db(login)

def calcular_resultado_final():
    global errors
    erros_totais_possiveis = 27
    # Calcular a nota total baseado na quantidade de erros
    notal_total = (100 / erros_totais_possiveis) * (erros_totais_possiveis - errors)

    # Exibir os resultados com f-strings
    print(f"\n\nForam identificados {errors} erros de um total de {erros_totais_possiveis}\n")
    print(f"Nota Total: {notal_total}")

# Rodando os testes
if __name__ == "__main__":
    test_registrar_usuario()
    test_atualizar_usuario()
    test_trocar_senha()
    test_excluir_usuario()
    test_pegar_detalhes_usuario()
    test_pegar_detalhes_produto()
    test_atualizar_produto()
    test_excluir_produto()
    test_pegar_produtos()
    calcular_resultado_final()